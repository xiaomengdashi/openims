#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ims::core {
struct DhcpConfig;
} // namespace ims::core

namespace ims::dhcp {

class DhcpServer {
public:
    explicit DhcpServer(const core::DhcpConfig& config);
    ~DhcpServer();

    DhcpServer(const DhcpServer&) = delete;
    DhcpServer& operator=(const DhcpServer&) = delete;

    bool start();
    void poll_once(int timeout_ms);

private:
    void process_discover(const std::vector<std::uint8_t>& packet, const std::string& remote_ip, std::uint16_t remote_port);
    void process_request(const std::vector<std::uint8_t>& packet, const std::string& remote_ip, std::uint16_t remote_port);
    std::vector<std::uint8_t> build_response(const std::vector<std::uint8_t>& request, uint8_t message_type, const std::string& client_mac);
    void add_option(std::vector<std::uint8_t>& packet, size_t& offset, std::uint8_t option_code, const std::vector<std::uint8_t>& option_value);

    const core::DhcpConfig& config_;
    int socket_fd_;
};

} // namespace ims::dhcp
