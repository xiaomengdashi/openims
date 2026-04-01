#pragma once

#include "src/n5/qos_policy.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ims::n5 {

// 3GPP TS 29.514 - Npcf_PolicyAuthorization Service API

// Network Slice Identifier (S-NSSAI)
struct Snssai {
  std::optional<uint8_t> sst;           // Slice Service Type (1-255)
  std::optional<std::string> sd;         // Slice Differentiator (hex string)
};

// PDU Session information from 5G access
struct PduSessionInfo {
  std::string pdu_session_id;            // PDU Session ID (1-255)
  std::string supi;                      // Subscriber Permanent Identifier (IMSI-based)
  std::string dnn;                       // Data Network Name (e.g., "ims")
  Snssai snssai;                         // Network Slice
  std::string ue_ipv4;                   // UE IPv4 address
  std::optional<std::string> ue_ipv6;    // UE IPv6 prefix
};

// Media sub-component (3GPP TS 29.514 MediaSubComponent)
struct MediaSubComponent {
  uint16_t f_num{0};                     // Flow number
  std::optional<uint16_t> f_port;        // Flow port
  std::vector<std::string> f_descs;      // Flow descriptions (IP filter rules)

  // ToJson
  std::string toJson() const;
  static std::optional<MediaSubComponent> fromJson(const std::string& json);
};

// Media component for AppSession (3GPP TS 29.514 MediaComponent)
struct MediaComponent {
  int med_com_id{0};                     // Media Component Identifier
  std::string med_type;                  // "AUDIO", "VIDEO", "DATA", "APPLICATION", etc.
  uint16_t med_com_status{0};            // 0=disabled, 1=enabled
  std::optional<uint16_t> mar_bw_dl;     // Max Requested Bandwidth Downlink (bps)
  std::optional<uint16_t> mar_bw_ul;     // Max Requested Bandwidth Uplink (bps)
  std::optional<uint16_t> mir_bw_dl;     // Min Requested Bandwidth Downlink (bps)
  std::optional<uint16_t> mir_bw_ul;     // Min Requested Bandwidth Uplink (bps)
  std::optional<int> rr_bw;              // Recommended Bandwidth
  std::optional<std::string> codecs;     // Codec information
  std::optional<int> f_status;           // Flow status
  std::vector<MediaSubComponent> med_sub_comps; // Media sub-components

  std::string toJson() const;
  static std::optional<MediaComponent> fromJson(const std::string& json);
};

// Service Info Status (3GPP TS 29.514)
enum class ServiceInfoStatus {
  FINAL_OPERATION = 1,
  PRELIMINARY_OPERATION = 2
};

// SIP Forking Indication (3GPP TS 29.514)
enum class SipForkingIndication {
  SINGLE_DIALOG = 0,
  SEVERAL_DIALOGS = 1
};

// Events subscirption (3GPP TS 29.514 EventsSubscReqData)
struct EventsSubscReqData {
  std::vector<std::string> events;       // Event types to subscribe
  std::optional<std::string> notif_uri;  // Notification URI
  std::optional<std::string> notif_id;   // Notification Correlation ID

  std::string toJson() const;
};

// AF application identifier context
struct AfRoutRequirement {
  std::string af_app_id;                 // AF Application Identifier
  std::optional<std::string> af_route_info; // AF routing information

  std::string toJson() const;
};

// AppSession Context Request Data (3GPP TS 29.514 AppSessionContextReqData)
struct AppSessionContextReqData {
  std::string af_app_id;                 // AF Application Identifier
  std::string af_charg_id;               // AF Charging Identifier
  std::string af_req_id;                 // AF Request Identifier (call-id)
  std::optional<std::string> ue_ipv4;    // UE IPv4 address
  std::optional<std::string> ue_ipv6;    // UE IPv6 prefix
  std::optional<std::string> ue_mac;     // UE MAC address

  // Reference IDs for resources
  std::vector<int> ref_pcu_ids;          // Reference to PC5 unicast signaling

  // Service information
  std::optional<ServiceInfoStatus> serv_inf_status;
  std::vector<MediaComponent> med_components;
  std::optional<EventsSubscReqData> ev_subsc;

  // SIP-specific
  std::optional<SipForkingIndication> sip_fork_ind;

  // Additional context
  std::optional<Snssai> slice_info;
  std::optional<std::string> dnn;
  std::optional<std::string> supi;       // GPSI or SUPI

  std::string toJson() const;
  static std::optional<AppSessionContextReqData> fromJson(const std::string& json);
};

// AppSession Context (3GPP TS 29.514 AppSessionContext)
struct AppSessionContext {
  std::optional<std::string> app_session_id;  // Assigned by PCF
  AppSessionContextReqData asc_req_data;

  std::string toJson() const;
  static std::optional<AppSessionContext> fromJson(const std::string& json);
};

// AppSession Context Update Data (3GPP TS 29.514 AppSessionContextUpdateData)
struct AppSessionContextUpdateData {
  std::optional<std::string> af_app_id;
  std::optional<std::string> af_charg_id;
  std::optional<std::string> af_req_id;
  std::optional<ServiceInfoStatus> serv_inf_status;
  std::vector<MediaComponent> med_components;
  std::optional<EventsSubscReqData> ev_subsc;
  std::optional<SipForkingIndication> sip_fork_ind;

  std::string toJson() const;
};

// PCF response: Events Notification (3GPP TS 29.514 EventsNotification)
struct EventsNotification {
  std::string app_session_id;
  std::vector<std::string> events;
  std::optional<std::string> cause;

  static std::optional<EventsNotification> fromJson(const std::string& json);
};

// PCF response: Policy Decision (simplified)
struct PolicyDecision {
  std::string app_session_id;
  std::vector<std::string> authorized_qo_s;  // Authorized QoS references

  static std::optional<PolicyDecision> fromJson(const std::string& json);
};

// Termination cause codes
enum class TerminationCause {
  UNSPECIFIED = 0,
  PDU_SESSION_RELEASE = 1,
  INSUFFICIENT_RESOURCES = 2,
  NETWORK_FAILURE = 3
};

// Termination Info
struct TerminationInfo {
  std::string app_session_id;
  TerminationCause term_cause{TerminationCause::UNSPECIFIED};
  std::optional<std::string> resource_uri;

  std::string toJson() const;
};

// Utility functions for JSON handling
namespace json_utils {

// Simple JSON string escaping
std::string escapeJson(const std::string& s);

// Simple JSON value writing helpers
std::string writeString(const std::string& key, const std::string& value);
std::string writeInt(const std::string& key, int value);
std::string writeUint(const std::string& key, uint16_t value);
std::string writeBool(const std::string& key, bool value);

// Simple JSON parsing helpers
std::optional<std::string> parseString(const std::string& json, const std::string& key);
std::optional<int> parseInt(const std::string& json, const std::string& key);
std::optional<uint16_t> parseUint(const std::string& json, const std::string& key);

} // namespace json_utils

} // namespace ims::n5
