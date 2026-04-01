#include "src/sip/pani_parser.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <unordered_map>

namespace ims::sip {

namespace {

// Trim whitespace from string
std::string trim(const std::string& s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

// Convert to lowercase
std::string toLower(const std::string& s) {
  std::string result = s;
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return result;
}

// Parse semicolon-separated parameters
std::unordered_map<std::string, std::string> parseParams(const std::string& param_str) {
  std::unordered_map<std::string, std::string> params;
  std::istringstream iss(param_str);
  std::string token;

  while (std::getline(iss, token, ';')) {
    token = trim(token);
    if (token.empty()) continue;

    size_t eq_pos = token.find('=');
    if (eq_pos != std::string::npos) {
      std::string key = trim(token.substr(0, eq_pos));
      std::string value = trim(token.substr(eq_pos + 1));
      // Remove quotes if present
      if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
      }
      params[toLower(key)] = value;
    } else {
      params[toLower(token)] = "";
    }
  }

  return params;
}

} // namespace

std::optional<AccessNetworkInfo> parsePani(const std::string& pani_header) {
  if (pani_header.empty()) {
    return std::nullopt;
  }

  AccessNetworkInfo info;

  // Split into access-type and parameters
  size_t semicolon_pos = pani_header.find(';');
  std::string access_type = pani_header;
  std::string param_str;

  if (semicolon_pos != std::string::npos) {
    access_type = trim(pani_header.substr(0, semicolon_pos));
    param_str = pani_header.substr(semicolon_pos + 1);
  }

  info.access_type = trim(access_type);

  // Parse parameters
  auto params = parseParams(param_str);

  // Map standard PANI parameter names (3GPP TS 24.229)
  // Note: parameter names are case-insensitive

  // 5G NR parameters
  if (params.count("utran-cell-id-3gpp")) {
    info.utran_cell_id = params["utran-cell-id-3gpp"];
  }
  if (params.count("nr-cell-id")) {
    info.nr_cell_id = params["nr-cell-id"];
  }
  if (params.count("nr-tac")) {
    info.nr_tac = params["nr-tac"];
  }
  if (params.count("gnb-id")) {
    info.gnb_id = params["gnb-id"];
  }

  // PDU Session parameters (5G)
  if (params.count("pdu-session-id")) {
    info.pdu_session_id = params["pdu-session-id"];
  }
  if (params.count("dnn")) {
    info.dnn = params["dnn"];
  }
  if (params.count("snssai") || params.count("s-nssai")) {
    info.snssai = params.count("snssai") ? params["snssai"] : params["s-nssai"];
  }

  // LTE/EPS parameters
  if (params.count("eutran-cell-id-3gpp") || params.count("eutra-cell-id")) {
    info.eutra_cell_id = params.count("eutran-cell-id-3gpp")
        ? params["eutran-cell-id-3gpp"]
        : params["eutra-cell-id"];
  }
  if (params.count("tac")) {
    info.tac = params["tac"];
  }

  // Legacy parameters
  if (params.count("cgi-3gpp") || params.count("cgi")) {
    info.cgi = params.count("cgi-3gpp") ? params["cgi-3gpp"] : params["cgi"];
  }
  if (params.count("geran-cell-id")) {
    info.geran_cell_id = params["geran-cell-id"];
  }

  // 5G specific identifiers
  if (params.count("5g-s-tmsi") || params.count("fiveg-s-tmsi")) {
    info.fiveg_s_tmsi = params.count("5g-s-tmsi") ? params["5g-s-tmsi"] : params["fiveg-s-tmsi"];
  }
  if (params.count("guami")) {
    info.guami = params["guami"];
  }

  return info;
}

bool is5GNR(const AccessNetworkInfo& info) {
  std::string access_type_lower = toLower(info.access_type);

  // Check for 5G NR access type
  if (access_type_lower == "3gpp-nr" ||
      access_type_lower == "nr" ||
      access_type_lower == "5g-nr" ||
      access_type_lower == "3gpp-5g") {
    return true;
  }

  // Also check for 5G-specific parameters
  if (info.pdu_session_id || info.nr_cell_id || info.gnb_id) {
    return true;
  }

  return false;
}

bool is4GLTE(const AccessNetworkInfo& info) {
  std::string access_type_lower = toLower(info.access_type);

  // Check for 4G LTE access types
  if (access_type_lower == "3gpp-eeps" ||
      access_type_lower == "3gpp-eps" ||
      access_type_lower == "eps" ||
      access_type_lower == "lte" ||
      access_type_lower == "eutran" ||
      access_type_lower == "3gpp-eutran" ||
      access_type_lower == "4g") {
    return true;
  }

  // Check for LTE-specific parameters
  if (info.eutra_cell_id && !is5GNR(info)) {
    return true;
  }

  return false;
}

bool is3GPP(const AccessNetworkInfo& info) {
  std::string access_type_lower = toLower(info.access_type);

  // Check for 3GPP access types
  return access_type_lower.find("3gpp") != std::string::npos ||
         is5GNR(info) || is4GLTE(info) ||
         access_type_lower == "utran" ||
         access_type_lower == "geran";
}

std::string getAccessTechnologyName(const AccessNetworkInfo& info) {
  if (is5GNR(info)) {
    return "5G NR";
  }
  if (is4GLTE(info)) {
    return "4G LTE";
  }

  std::string access_type_lower = toLower(info.access_type);
  if (access_type_lower.find("non-3gpp") != std::string::npos) {
    return "Non-3GPP";
  }
  if (access_type_lower == "utran" || access_type_lower.find("3gpp-utran") != std::string::npos) {
    return "3G UTRAN";
  }
  if (access_type_lower == "geran" || access_type_lower.find("3gpp-geran") != std::string::npos) {
    return "2G GERAN";
  }

  return info.access_type.empty() ? "Unknown" : info.access_type;
}

std::optional<int> getPduSessionIdInt(const AccessNetworkInfo& info) {
  if (!info.pdu_session_id) {
    return std::nullopt;
  }

  try {
    int id = std::stoi(*info.pdu_session_id);
    if (id >= 1 && id <= 255) {
      return id;
    }
  } catch (...) {
    // Invalid format
  }

  return std::nullopt;
}

std::string buildPaniHeader(const AccessNetworkInfo& info) {
  if (info.access_type.empty()) {
    return "";
  }

  std::ostringstream oss;
  oss << info.access_type;

  // Add 5G NR parameters
  if (info.nr_cell_id) {
    oss << ";nr-cell-id=" << *info.nr_cell_id;
  } else if (info.utran_cell_id) {
    oss << ";utran-cell-id-3gpp=" << *info.utran_cell_id;
  }

  if (info.nr_tac) {
    oss << ";nr-tac=" << *info.nr_tac;
  }
  if (info.gnb_id) {
    oss << ";gnb-id=" << *info.gnb_id;
  }

  // Add PDU Session parameters
  if (info.pdu_session_id) {
    oss << ";pdu-session-id=" << *info.pdu_session_id;
  }
  if (info.dnn) {
    oss << ";dnn=" << *info.dnn;
  }
  if (info.snssai) {
    oss << ";snssai=" << *info.snssai;
  }

  // Add LTE parameters
  if (info.eutra_cell_id) {
    oss << ";eutran-cell-id-3gpp=" << *info.eutra_cell_id;
  }
  if (info.tac) {
    oss << ";tac=" << *info.tac;
  }

  return oss.str();
}

} // namespace ims::sip
