#include "ims/dhcp/dhcp_server.hpp"
#include "ims/core/config.hpp"
#include "ims/core/log.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

namespace ims::dhcp {

// DHCP message types
enum class DhcpMessageType {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    ACK = 5
};

// DHCP options
enum class DhcpOption {
    SUBNET_MASK = 1,
    ROUTER = 3,
    DNS_SERVER = 6,
    DOMAIN_NAME = 15,  // Task specifies this for P-CSCF address
    DHCP_MESSAGE_TYPE = 53,
    SERVER_IDENTIFIER = 54,
    LEASE_TIME = 51,
    PARAMETER_REQUEST_LIST = 55,
    END = 255
};

// Convert IP string to 32-bit integer (host byte order)
static uint32_t ip_to_uint32(const std::string& ip) {
    in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    return ntohl(addr.s_addr);
}

// Convert 32-bit integer (host byte order) to IP string
static std::string uint32_to_ip(uint32_t ip) {
    in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

DhcpServer::DhcpServer(const core::DhcpConfig& config)
    : config_(config)
    , socket_fd_(-1) {}

DhcpServer::~DhcpServer() {
    if (socket_fd_ != -1) {
        close(socket_fd_);
    }
}

bool DhcpServer::start() {
    // Create UDP socket
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd_ < 0) {
        LOG_ERROR("Failed to create DHCP socket: {}", strerror(errno));
        return false;
    }

    // Set SO_REUSEADDR to allow binding to the same port if needed
    int reuse = 1;
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        LOG_ERROR("Failed to set SO_REUSEADDR: {}", strerror(errno));
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    // Set SO_BROADCAST to allow sending broadcast packets
    int broadcast = 1;
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        LOG_ERROR("Failed to set SO_BROADCAST: {}", strerror(errno));
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    // Bind to the specified IP and port
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, config_.bind_ip.c_str(), &server_addr.sin_addr);
    server_addr.sin_port = htons(config_.port);

    if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        LOG_ERROR("Failed to bind DHCP socket to {}:{} - {}", config_.bind_ip, config_.port, strerror(errno));
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    LOG_INFO("DHCP server started on {}:{}", config_.bind_ip, config_.port);
    LOG_INFO("P-CSCF address for Option 15: {}", config_.pcscf_address);
    LOG_INFO("IP pool: {} to {}", config_.pool_start, config_.pool_end);
    LOG_INFO("Lease time: {} seconds", config_.lease_time_seconds);

    return true;
}

void DhcpServer::poll_once(int timeout_ms) {
    if (socket_fd_ < 0) {
        LOG_ERROR("DHCP server not started");
        return;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(socket_fd_, &read_fds);

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int result = select(socket_fd_ + 1, &read_fds, nullptr, nullptr, &tv);
    if (result < 0) {
        LOG_ERROR("select() failed: {}", strerror(errno));
        return;
    } else if (result == 0) {
        // Timeout, no packets to process
        return;
    }

    // There's a packet to read
    std::vector<uint8_t> buffer(1024);
    sockaddr_in client_addr{};
    socklen_t client_addr_len = sizeof(client_addr);

    ssize_t bytes_received = recvfrom(
        socket_fd_, buffer.data(), buffer.size(), 0,
        reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len
    );

    if (bytes_received < 0) {
        LOG_ERROR("recvfrom() failed: {}", strerror(errno));
        return;
    }

    LOG_DEBUG("Received {} bytes from {}:{}", bytes_received,
              inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // Check magic cookie (must be at least 240 bytes)
    if (bytes_received < 240) {
        LOG_DEBUG("DHCP packet too short: {} bytes", bytes_received);
        return;
    }

    // Verify DHCP magic cookie (99, 130, 83, 99)
    const uint32_t expected_magic = 0x63538263;
    uint32_t magic = ntohl(*reinterpret_cast<uint32_t*>(buffer.data() + 236));
    if (magic != expected_magic) {
        LOG_DEBUG("Invalid DHCP magic cookie: 0x{:08x}", magic);
        return;
    }

    // Extract client MAC address (from BOOTP header)
    std::string client_mac;
    {
        const uint8_t* mac = buffer.data() + 28;
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        client_mac = mac_str;
    }

    // Parse DHCP message type from options
    DhcpMessageType msg_type = static_cast<DhcpMessageType>(0);
    size_t option_offset = 240;
    while (option_offset < static_cast<size_t>(bytes_received)) {
        uint8_t option_code = buffer[option_offset++];
        if (option_code == static_cast<uint8_t>(DhcpOption::END)) {
            break;
        } else if (option_code == 0) {
            // Pad option, skip
            continue;
        }

        if (option_offset >= static_cast<size_t>(bytes_received)) {
            break;
        }

        uint8_t option_len = buffer[option_offset++];
        if (option_offset + option_len > static_cast<size_t>(bytes_received)) {
            break;
        }

        if (option_code == static_cast<uint8_t>(DhcpOption::DHCP_MESSAGE_TYPE) && option_len == 1) {
            msg_type = static_cast<DhcpMessageType>(buffer[option_offset]);
        }

        option_offset += option_len;
    }

    // Process the message
    switch (msg_type) {
        case DhcpMessageType::DISCOVER:
            LOG_INFO("DHCPDISCOVER from {}", client_mac);
            process_discover(buffer, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            break;
        case DhcpMessageType::REQUEST:
            LOG_INFO("DHCPREQUEST from {}", client_mac);
            process_request(buffer, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            break;
        default:
            LOG_DEBUG("Unhandled DHCP message type: {}", static_cast<int>(msg_type));
            break;
    }
}

void DhcpServer::process_discover(const std::vector<uint8_t>& packet, const std::string& remote_ip, std::uint16_t remote_port) {
    // Extract client MAC address (from BOOTP header)
    const uint8_t* mac = packet.data() + 28;
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    std::string client_mac = mac_str;

    // Build and send OFFER
    auto response = build_response(packet, static_cast<uint8_t>(DhcpMessageType::OFFER), client_mac);
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(68);  // DHCP client port

    // If request came from 0.0.0.0 (broadcast), respond to broadcast
    if (remote_ip == "0.0.0.0") {
        dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        LOG_DEBUG("Responding DHCPOFFER to broadcast");
    } else {
        inet_pton(AF_INET, remote_ip.c_str(), &dest_addr.sin_addr);
        LOG_DEBUG("Responding DHCPOFFER to {}", remote_ip);
    }

    ssize_t bytes_sent = sendto(
        socket_fd_, response.data(), response.size(), 0,
        reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr)
    );

    if (bytes_sent < 0) {
        LOG_ERROR("sendto() failed for DHCPOFFER: {}", strerror(errno));
    }
}

void DhcpServer::process_request(const std::vector<uint8_t>& packet, const std::string& remote_ip, std::uint16_t remote_port) {
    // Extract client MAC address (from BOOTP header)
    const uint8_t* mac = packet.data() + 28;
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    std::string client_mac = mac_str;

    // Build and send ACK
    auto response = build_response(packet, static_cast<uint8_t>(DhcpMessageType::ACK), client_mac);
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(68);  // DHCP client port

    // If request came from 0.0.0.0 (broadcast), respond to broadcast
    if (remote_ip == "0.0.0.0") {
        dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        LOG_DEBUG("Responding DHCPACK to broadcast");
    } else {
        inet_pton(AF_INET, remote_ip.c_str(), &dest_addr.sin_addr);
        LOG_DEBUG("Responding DHCPACK to {}", remote_ip);
    }

    ssize_t bytes_sent = sendto(
        socket_fd_, response.data(), response.size(), 0,
        reinterpret_cast<sockaddr*>(&dest_addr), sizeof(dest_addr)
    );

    if (bytes_sent < 0) {
        LOG_ERROR("sendto() failed for DHCPACK: {}", strerror(errno));
    }
}

std::vector<std::uint8_t> DhcpServer::build_response(const std::vector<uint8_t>& request, uint8_t message_type, const std::string& client_mac) {
    std::vector<uint8_t> response(576);  // Standard DHCP response size
    std::memset(response.data(), 0, response.size());

    // Copy BOOTP header from request (xid, flags, chaddr)
    std::memcpy(response.data(), request.data(), 236);

    // Set BOOTP op code: 2 for reply
    response[0] = 2;

    // Set server identifier (sname field offset 10)
    in_addr server_in_addr{};
    inet_pton(AF_INET, config_.bind_ip.c_str(), &server_in_addr);
    std::memcpy(response.data() + 10, &server_in_addr, 4);

    // Allocate client IP from pool (round-robin)
    static uint32_t current_ip = 0;
    uint32_t pool_start = ip_to_uint32(config_.pool_start);
    uint32_t pool_end = ip_to_uint32(config_.pool_end);

    if (current_ip < pool_start || current_ip > pool_end) {
        current_ip = pool_start;
    }

    uint32_t allocated_ip = current_ip;

    // Increment for next allocation (round-robin)
    current_ip++;
    if (current_ip > pool_end) {
        current_ip = pool_start;
    }

    // Set yiaddr (your IP address)
    in_addr_t yiaddr = htonl(allocated_ip);
    std::memcpy(response.data() + 16, &yiaddr, 4);

    // Set magic cookie
    const uint32_t magic = htonl(0x63538263);
    std::memcpy(response.data() + 236, &magic, 4);

    // Build options
    size_t offset = 240;

    // Add options using helper method
    add_option(response, offset, static_cast<uint8_t>(DhcpOption::DHCP_MESSAGE_TYPE), {message_type});
    add_option(response, offset, static_cast<uint8_t>(DhcpOption::SERVER_IDENTIFIER),
               std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&server_in_addr),
                                     reinterpret_cast<uint8_t*>(&server_in_addr) + 4));

    // Lease time (4 bytes, network order)
    uint32_t lease_time = htonl(config_.lease_time_seconds);
    add_option(response, offset, static_cast<uint8_t>(DhcpOption::LEASE_TIME),
               std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&lease_time),
                                     reinterpret_cast<uint8_t*>(&lease_time) + 4));

    // Subnet mask: 255.255.255.0
    uint32_t subnet_mask = htonl(0xffffff00);
    add_option(response, offset, static_cast<uint8_t>(DhcpOption::SUBNET_MASK),
               std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&subnet_mask),
                                     reinterpret_cast<uint8_t*>(&subnet_mask) + 4));

    // Option 15: Domain Name (P-CSCF address as string)
    add_option(response, offset, static_cast<uint8_t>(DhcpOption::DOMAIN_NAME),
               std::vector<uint8_t>(config_.pcscf_address.begin(), config_.pcscf_address.end()));

    // End option
    response[offset++] = static_cast<uint8_t>(DhcpOption::END);

    // Trim response to actual size
    response.resize(offset);

    std::string msg_str = (message_type == static_cast<uint8_t>(DhcpMessageType::OFFER)) ? "DHCPOFFER" : "DHCPACK";
    LOG_INFO("{}: Allocated IP {} to {}", msg_str, uint32_to_ip(allocated_ip), client_mac);

    return response;
}

void DhcpServer::add_option(std::vector<std::uint8_t>& packet, size_t& offset, uint8_t option_code, const std::vector<std::uint8_t>& option_value) {
    packet[offset++] = option_code;
    packet[offset++] = static_cast<uint8_t>(option_value.size());
    std::memcpy(packet.data() + offset, option_value.data(), option_value.size());
    offset += option_value.size();
}

} // namespace ims::dhcp
