#include "src/n5/n5_client.hpp"

#ifdef IMS_HAS_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

#include <spdlog/spdlog.h>

#include <array>
#include <cstring>
#include <mutex>
#include <sstream>
#include <unordered_map>

// For socket operations
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace ims::n5 {

namespace {

// HTTP/2 client session data
struct HttpSession {
  int socket_fd{-1};
  std::string host;
  uint16_t port{0};
  bool connected{false};
  std::string response_buffer;
  int response_status{0};
  std::string location_header;  // For resource ID extraction
};

// Simple HTTP/2 client using raw sockets and nghttp2
class NgHttp2Client {
public:
  explicit NgHttp2Client(const N5ClientConfig& config) : config_(config) {}

  bool connect() {
    if (session_.connected) {
      return true;
    }

    // Create socket
    session_.socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (session_.socket_fd < 0) {
      spdlog::error("[N5] Failed to create socket: {}", strerror(errno));
      return false;
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = config_.timeout_ms / 1000;
    tv.tv_usec = (config_.timeout_ms % 1000) * 1000;
    setsockopt(session_.socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(session_.socket_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Resolve and connect
    struct hostent* host = gethostbyname(config_.pcf_address.c_str());
    if (!host) {
      spdlog::error("[N5] Failed to resolve host: {}", config_.pcf_address);
      close(session_.socket_fd);
      session_.socket_fd = -1;
      return false;
    }

    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config_.pcf_port);
    std::memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);

    if (::connect(session_.socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
      spdlog::error("[N5] Failed to connect to {}:{}", config_.pcf_address, config_.pcf_port);
      close(session_.socket_fd);
      session_.socket_fd = -1;
      return false;
    }

    session_.host = config_.pcf_address;
    session_.port = config_.pcf_port;
    session_.connected = true;

    spdlog::info("[N5] Connected to PCF at {}:{}", config_.pcf_address, config_.pcf_port);
    return true;
  }

  void disconnect() {
    if (session_.socket_fd >= 0) {
      close(session_.socket_fd);
      session_.socket_fd = -1;
    }
    session_.connected = false;
    session_.response_buffer.clear();
  }

  // Perform HTTP POST request (simplified HTTP/1.1 for MVP)
  std::pair<int, std::string> post(const std::string& path, const std::string& body) {
    return doRequest("POST", path, body);
  }

  // Perform HTTP PATCH request
  std::pair<int, std::string> patch(const std::string& path, const std::string& body) {
    return doRequest("PATCH", path, body);
  }

  // Perform HTTP DELETE request
  std::pair<int, std::string> del(const std::string& path) {
    return doRequest("DELETE", path, "");
  }

  const std::string& getLocationHeader() const { return session_.location_header; }

private:
  std::pair<int, std::string> doRequest(const std::string& method,
                                         const std::string& path,
                                         const std::string& body) {
    if (!session_.connected && !connect()) {
      return {-1, "Connection failed"};
    }

    // Build HTTP request (HTTP/1.1 for simplicity, can upgrade to HTTP/2)
    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n";
    req << "Host: " << session_.host << ":" << session_.port << "\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Accept: application/json\r\n";
    if (!body.empty()) {
      req << "Content-Length: " << body.size() << "\r\n";
    }
    req << "Connection: keep-alive\r\n";
    req << "\r\n";
    if (!body.empty()) {
      req << body;
    }

    std::string request = req.str();

    // Send request
    ssize_t sent = send(session_.socket_fd, request.c_str(), request.size(), 0);
    if (sent < 0) {
      spdlog::error("[N5] Failed to send request: {}", strerror(errno));
      disconnect();
      return {-1, "Send failed"};
    }

    // Receive response
    session_.response_buffer.clear();
    session_.location_header.clear();
    std::array<char, 4096> buffer;

    bool headers_complete = false;
    bool in_location = false;

    while (true) {
      ssize_t received = recv(session_.socket_fd, buffer.data(), buffer.size(), 0);
      if (received <= 0) {
        if (received == 0) {
          // Connection closed by peer
          break;
        }
        spdlog::error("[N5] Failed to receive response: {}", strerror(errno));
        disconnect();
        return {-1, "Receive failed"};
      }

      session_.response_buffer.append(buffer.data(), received);

      // Check if we have complete response (simplified)
      if (session_.response_buffer.find("\r\n\r\n") != std::string::npos) {
        // Check Content-Length for body completion
        size_t header_end = session_.response_buffer.find("\r\n\r\n");
        std::string headers = session_.response_buffer.substr(0, header_end);

        // Extract status code
        if (session_.response_status == 0) {
          size_t space_pos = headers.find(' ');
          if (space_pos != std::string::npos) {
            session_.response_status = std::stoi(headers.substr(space_pos + 1, 3));
          }
        }

        // Extract Location header
        size_t loc_pos = headers.find("Location:");
        if (loc_pos == std::string::npos) {
          loc_pos = headers.find("location:");
        }
        if (loc_pos != std::string::npos) {
          size_t line_start = loc_pos;
          size_t value_start = headers.find(':', line_start) + 1;
          size_t line_end = headers.find("\r\n", value_start);
          if (line_end != std::string::npos) {
            session_.location_header = headers.substr(value_start, line_end - value_start);
            // Trim whitespace
            size_t start = session_.location_header.find_first_not_of(" \t");
            size_t end = session_.location_header.find_last_not_of(" \t\r\n");
            if (start != std::string::npos && end != std::string::npos) {
              session_.location_header = session_.location_header.substr(start, end - start + 1);
            }
          }
        }

        // Find Content-Length
        size_t body_start = header_end + 4;
        size_t cl_pos = headers.find("Content-Length:");
        if (cl_pos == std::string::npos) {
          cl_pos = headers.find("content-length:");
        }
        if (cl_pos != std::string::npos) {
          size_t cl_value_start = headers.find(':', cl_pos) + 1;
          size_t cl_line_end = headers.find("\r\n", cl_value_start);
          int content_length = std::stoi(headers.substr(cl_value_start, cl_line_end - cl_value_start));

          if (session_.response_buffer.size() >= body_start + content_length) {
            break;  // Complete response received
          }
        } else {
          // No Content-Length, assume response is complete after headers
          break;
        }
      }
    }

    // Extract body
    size_t body_start = session_.response_buffer.find("\r\n\r\n");
    std::string response_body;
    if (body_start != std::string::npos) {
      response_body = session_.response_buffer.substr(body_start + 4);
    }

    return {session_.response_status, response_body};
  }

  N5ClientConfig config_;
  HttpSession session_;
};

} // namespace

// N5 Client implementation
class N5ClientImpl : public IN5Client {
public:
  explicit N5ClientImpl(const N5ClientConfig& config)
      : config_(config), http_client_(std::make_unique<NgHttp2Client>(config)) {}

  ~N5ClientImpl() override {
    shutdown();
  }

  bool initialize() override {
    if (!config_.enabled) {
      spdlog::info("[N5] N5 client disabled, skipping initialization");
      return true;
    }

    std::lock_guard<std::mutex> lock(mutex_);

#ifdef IMS_HAS_NGHTTP2
    spdlog::info("[N5] Initializing N5 client with nghttp2 support");
    if (!http_client_->connect()) {
      spdlog::error("[N5] Failed to connect to PCF");
      return false;
    }
    return true;
#else
    spdlog::warn("[N5] nghttp2 not available, N5 client will operate in stub mode");
    return true;
#endif
  }

  void shutdown() override {
    std::lock_guard<std::mutex> lock(mutex_);
    http_client_->disconnect();
    sessions_.clear();
    spdlog::info("[N5] N5 client shut down");
  }

  CreateSessionResult createSession(
      const std::string& call_id,
      const std::vector<MediaComponent>& media,
      const PduSessionInfo& pdu_session,
      const std::optional<EventsSubscReqData>& events_subsc) override {

    CreateSessionResult result;

    if (!config_.enabled) {
      result.success = true;
      result.resource_id = "stub-" + call_id;
      return result;
    }

    std::lock_guard<std::mutex> lock(mutex_);

#ifdef IMS_HAS_NGHTTP2
    // Build request body
    AppSessionContext context;
    context.asc_req_data.af_app_id = "ims";
    context.asc_req_data.af_charg_id = call_id;
    context.asc_req_data.af_req_id = call_id;
    context.asc_req_data.ue_ipv4 = pdu_session.ue_ipv4;
    context.asc_req_data.dnn = pdu_session.dnn;
    context.asc_req_data.supi = pdu_session.supi;
    context.asc_req_data.med_components = media;
    context.asc_req_data.ev_subsc = events_subsc;
    context.asc_req_data.serv_inf_status = ServiceInfoStatus::PRELIMINARY_OPERATION;

    std::string body = context.toJson();

    spdlog::debug("[N5] Creating AppSession for call {}: {}", call_id, body);

    auto [status, response] = http_client_->post("/npcf-policyauthorization/v1/app-sessions", body);

    if (status == 201 || status == 200) {
      result.success = true;

      // Extract resource ID from Location header
      const std::string& location = http_client_->getLocationHeader();
      if (!location.empty()) {
        // Extract resource ID from Location URL
        size_t last_slash = location.find_last_of('/');
        if (last_slash != std::string::npos) {
          result.resource_id = location.substr(last_slash + 1);
        } else {
          result.resource_id = location;
        }
      }

      if (result.resource_id.empty()) {
        // Try to parse from response body
        auto parsed = AppSessionContext::fromJson(response);
        if (parsed && parsed->app_session_id) {
          result.resource_id = *parsed->app_session_id;
        }
      }

      // Store session mapping
      sessions_[call_id] = result.resource_id;

      spdlog::info("[N5] Created AppSession {} for call {}", result.resource_id, call_id);
    } else {
      result.success = false;
      result.error_message = "PCF returned status " + std::to_string(status) + ": " + response;
      spdlog::error("[N5] Failed to create AppSession: {}", result.error_message);
    }
#else
    result.success = true;
    result.resource_id = "stub-" + call_id;
    sessions_[call_id] = result.resource_id;
#endif

    return result;
  }

  UpdateSessionResult updateSession(
      const std::string& resource_id,
      const AppSessionContextUpdateData& update_data) override {

    UpdateSessionResult result;

    if (!config_.enabled) {
      result.success = true;
      return result;
    }

    std::lock_guard<std::mutex> lock(mutex_);

#ifdef IMS_HAS_NGHTTP2
    std::string body = update_data.toJson();
    std::string path = "/npcf-policyauthorization/v1/app-sessions/" + resource_id;

    spdlog::debug("[N5] Updating AppSession {}: {}", resource_id, body);

    auto [status, response] = http_client_->patch(path, body);

    if (status == 200 || status == 204) {
      result.success = true;
      spdlog::info("[N5] Updated AppSession {}", resource_id);
    } else {
      result.success = false;
      result.error_message = "PCF returned status " + std::to_string(status) + ": " + response;
      spdlog::error("[N5] Failed to update AppSession: {}", result.error_message);
    }
#else
    result.success = true;
#endif

    return result;
  }

  DeleteSessionResult deleteSession(const std::string& resource_id) override {
    DeleteSessionResult result;

    if (!config_.enabled) {
      result.success = true;
      return result;
    }

    std::lock_guard<std::mutex> lock(mutex_);

#ifdef IMS_HAS_NGHTTP2
    std::string path = "/npcf-policyauthorization/v1/app-sessions/" + resource_id;

    spdlog::debug("[N5] Deleting AppSession {}", resource_id);

    auto [status, response] = http_client_->del(path);

    if (status == 204 || status == 200 || status == 404) {
      result.success = true;

      // Remove from sessions map
      for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it->second == resource_id) {
          sessions_.erase(it);
          break;
        }
      }

      spdlog::info("[N5] Deleted AppSession {}", resource_id);
    } else {
      result.success = false;
      result.error_message = "PCF returned status " + std::to_string(status) + ": " + response;
      spdlog::error("[N5] Failed to delete AppSession: {}", result.error_message);
    }
#else
    result.success = true;
#endif

    return result;
  }

  void setNotificationCallback(NotificationCallback callback) override {
    notification_callback_ = std::move(callback);
  }

  const QosMappingConfig& getQosMapping() const override {
    return config_.qos_mapping;
  }

private:
  N5ClientConfig config_;
  std::unique_ptr<NgHttp2Client> http_client_;
  std::mutex mutex_;
  std::unordered_map<std::string, std::string> sessions_;  // call_id -> resource_id
  NotificationCallback notification_callback_;
};

std::unique_ptr<IN5Client> createN5Client(const N5ClientConfig& config) {
  return std::make_unique<N5ClientImpl>(config);
}

} // namespace ims::n5
