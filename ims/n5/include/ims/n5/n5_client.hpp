#pragma once

#include "ims/n5/n5_models.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace ims::n5 {

// N5 client configuration
struct N5ClientConfig {
  bool enabled{false};
  std::string pcf_address{"127.0.0.1"};
  uint16_t pcf_port{8080};
  int timeout_ms{5000};
  bool use_tls{false};
  QosMappingConfig qos_mapping;
};

// Result of N5 session creation
struct CreateSessionResult {
  bool success{false};
  std::string resource_id;        // AppSession resource ID from PCF
  std::string error_message;
};

// Result of N5 session update
struct UpdateSessionResult {
  bool success{false};
  std::string error_message;
};

// Result of N5 session deletion
struct DeleteSessionResult {
  bool success{false};
  std::string error_message;
};

// Callback for async notifications from PCF
using NotificationCallback = std::function<void(const EventsNotification&)>;

// N5 client interface (3GPP TS 29.514 Npcf_PolicyAuthorization)
class IN5Client {
public:
  virtual ~IN5Client() = default;

  // Initialize the client (connect to PCF)
  virtual bool initialize() = 0;

  // Shutdown the client
  virtual void shutdown() = 0;

  // Create an AppSession with PCF
  // POST /npcf-policyauthorization/v1/app-sessions
  virtual CreateSessionResult createSession(
      const std::string& call_id,
      const std::vector<MediaComponent>& media,
      const PduSessionInfo& pdu_session,
      const std::optional<EventsSubscReqData>& events_subsc = std::nullopt) = 0;

  // Update an existing AppSession
  // PATCH /npcf-policyauthorization/v1/app-sessions/{resourceId}
  virtual UpdateSessionResult updateSession(
      const std::string& resource_id,
      const AppSessionContextUpdateData& update_data) = 0;

  // Delete an AppSession
  // DELETE /npcf-policyauthorization/v1/app-sessions/{resourceId}
  virtual DeleteSessionResult deleteSession(const std::string& resource_id) = 0;

  // Set notification callback for async events from PCF
  virtual void setNotificationCallback(NotificationCallback callback) = 0;

  // Get QoS mapping configuration
  virtual const QosMappingConfig& getQosMapping() const = 0;
};

// Factory function to create N5 client
std::unique_ptr<IN5Client> createN5Client(const N5ClientConfig& config);

} // namespace ims::n5
