#pragma once

#include <optional>
#include <string>

namespace ims::sip {

// 5G Access Network Information extracted from P-Access-Network-Info header
// 3GPP TS 24.229 and 3GPP TS 29.500
struct AccessNetworkInfo {
  // Access type: "3GPP-NR", "3GPP-EPS", "non-3GPP", etc.
  std::string access_type;

  // 5G NR specific parameters
  std::optional<std::string> nr_cell_id;        // NR Cell Global Identity (NGCI)
  std::optional<std::string> nr_tac;            // NR Tracking Area Code
  std::optional<std::string> gnb_id;            // gNodeB ID

  // PDU Session information
  std::optional<std::string> pdu_session_id;    // PDU Session ID (1-255)
  std::optional<std::string> dnn;               // Data Network Name
  std::optional<std::string> snssai;            // S-NSSAI (Network Slice)

  // LTE/EPS parameters (for interworking)
  std::optional<std::string> eutra_cell_id;     // E-UTRA Cell Global Identity
  std::optional<std::string> tac;               // Tracking Area Code

  // Generic parameters
  std::optional<std::string> utran_cell_id;     // UTRAN Cell ID (legacy)
  std::optional<std::string> geran_cell_id;     // GERAN Cell ID (legacy)
  std::optional<std::string> cgi;               // Cell Global Identity (legacy)

  // Additional 5G parameters
  std::optional<std::string> fiveg_s_tmsi;      // 5G S-TMSI
  std::optional<std::string> guami;             // GUAMI
};

// Parse P-Access-Network-Info header value
// Example: "3GPP-NR;utran-cell-id-3gpp=1234567890abcdef;pdu-session-id=1"
std::optional<AccessNetworkInfo> parsePani(const std::string& pani_header);

// Check if the access network is 5G NR
bool is5GNR(const AccessNetworkInfo& info);

// Check if the access network is 4G LTE
bool is4GLTE(const AccessNetworkInfo& info);

// Check if the access network is 3GPP (NR or LTE)
bool is3GPP(const AccessNetworkInfo& info);

// Get the access technology name for logging
std::string getAccessTechnologyName(const AccessNetworkInfo& info);

// Extract PDU Session ID as integer (1-255)
std::optional<int> getPduSessionIdInt(const AccessNetworkInfo& info);

// Build a PANI header string from AccessNetworkInfo
std::string buildPaniHeader(const AccessNetworkInfo& info);

} // namespace ims::sip
