#include "src/n5/n5_models.hpp"

#include <algorithm>
#include <regex>
#include <sstream>

namespace ims::n5 {

// ============================================================================
// JSON Utilities
// ============================================================================

namespace json_utils {

std::string escapeJson(const std::string& s) {
  std::string result;
  result.reserve(s.size() * 2);

  for (char c : s) {
    switch (c) {
      case '"': result += "\\\""; break;
      case '\\': result += "\\\\"; break;
      case '\b': result += "\\b"; break;
      case '\f': result += "\\f"; break;
      case '\n': result += "\\n"; break;
      case '\r': result += "\\r"; break;
      case '\t': result += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          // Escape control characters
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
          result += buf;
        } else {
          result += c;
        }
    }
  }
  return result;
}

std::string writeString(const std::string& key, const std::string& value) {
  return "\"" + key + "\": \"" + escapeJson(value) + "\"";
}

std::string writeInt(const std::string& key, int value) {
  return "\"" + key + "\": " + std::to_string(value);
}

std::string writeUint(const std::string& key, uint16_t value) {
  return "\"" + key + "\": " + std::to_string(value);
}

std::string writeBool(const std::string& key, bool value) {
  return "\"" + key + "\": " + (value ? "true" : "false");
}

// Simple regex-based JSON string extraction
std::optional<std::string> parseString(const std::string& json, const std::string& key) {
  // Pattern: "key": "value" or "key": "value with \"escapes\""
  std::string pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*(?:\\\\\"[^\"]*)*)\"";
  std::regex re(pattern);
  std::smatch match;
  if (std::regex_search(json, match, re) && match.size() > 1) {
    std::string value = match[1].str();
    // Unescape basic sequences
    size_t pos = 0;
    while ((pos = value.find("\\\"", pos)) != std::string::npos) {
      value.replace(pos, 2, "\"");
      pos += 1;
    }
    return value;
  }
  return std::nullopt;
}

std::optional<int> parseInt(const std::string& json, const std::string& key) {
  std::string pattern = "\"" + key + "\"\\s*:\\s*(-?\\d+)";
  std::regex re(pattern);
  std::smatch match;
  if (std::regex_search(json, match, re) && match.size() > 1) {
    try {
      return std::stoi(match[1].str());
    } catch (...) {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

std::optional<uint16_t> parseUint(const std::string& json, const std::string& key) {
  auto val = parseInt(json, key);
  if (val && *val >= 0) {
    return static_cast<uint16_t>(*val);
  }
  return std::nullopt;
}

} // namespace json_utils

// ============================================================================
// MediaSubComponent
// ============================================================================

std::string MediaSubComponent::toJson() const {
  std::ostringstream oss;
  oss << "{";
  oss << json_utils::writeInt("fNum", f_num);
  if (f_port) {
    oss << ", " << json_utils::writeUint("fPort", *f_port);
  }
  if (!f_descs.empty()) {
    oss << ", \"fDescs\": [";
    for (size_t i = 0; i < f_descs.size(); ++i) {
      if (i > 0) oss << ", ";
      oss << "\"" << json_utils::escapeJson(f_descs[i]) << "\"";
    }
    oss << "]";
  }
  oss << "}";
  return oss.str();
}

std::optional<MediaSubComponent> MediaSubComponent::fromJson(const std::string& json) {
  MediaSubComponent comp;

  auto f_num = json_utils::parseInt(json, "fNum");
  if (!f_num) return std::nullopt;
  comp.f_num = static_cast<uint16_t>(*f_num);

  comp.f_port = json_utils::parseUint(json, "fPort");

  // Parse fDescs array (simplified)
  std::regex desc_re("\"fDescs\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch match;
  if (std::regex_search(json, match, desc_re) && match.size() > 1) {
    std::string descs_str = match[1].str();
    std::regex str_re("\"([^\"]+)\"");
    std::sregex_iterator it(descs_str.begin(), descs_str.end(), str_re);
    std::sregex_iterator end;
    while (it != end) {
      comp.f_descs.push_back((*it)[1].str());
      ++it;
    }
  }

  return comp;
}

// ============================================================================
// MediaComponent
// ============================================================================

std::string MediaComponent::toJson() const {
  std::ostringstream oss;
  oss << "{";
  oss << json_utils::writeInt("medComId", med_com_id);
  oss << ", " << json_utils::writeString("medType", med_type);

  if (med_com_status != 0) {
    oss << ", " << json_utils::writeInt("medComStatus", med_com_status);
  }
  if (mar_bw_dl) {
    oss << ", " << json_utils::writeUint("marBwDl", *mar_bw_dl);
  }
  if (mar_bw_ul) {
    oss << ", " << json_utils::writeUint("marBwUl", *mar_bw_ul);
  }
  if (mir_bw_dl) {
    oss << ", " << json_utils::writeUint("mirBwDl", *mir_bw_dl);
  }
  if (mir_bw_ul) {
    oss << ", " << json_utils::writeUint("mirBwUl", *mir_bw_ul);
  }
  if (codecs) {
    oss << ", " << json_utils::writeString("codecs", *codecs);
  }
  if (f_status) {
    oss << ", " << json_utils::writeInt("fStatus", *f_status);
  }

  if (!med_sub_comps.empty()) {
    oss << ", \"medSubComps\": [";
    for (size_t i = 0; i < med_sub_comps.size(); ++i) {
      if (i > 0) oss << ", ";
      oss << med_sub_comps[i].toJson();
    }
    oss << "]";
  }

  oss << "}";
  return oss.str();
}

std::optional<MediaComponent> MediaComponent::fromJson(const std::string& json) {
  MediaComponent comp;

  auto id = json_utils::parseInt(json, "medComId");
  if (!id) return std::nullopt;
  comp.med_com_id = *id;

  auto type = json_utils::parseString(json, "medType");
  if (!type) return std::nullopt;
  comp.med_type = *type;

  comp.med_com_status = json_utils::parseInt(json, "medComStatus").value_or(0);
  comp.mar_bw_dl = json_utils::parseUint(json, "marBwDl");
  comp.mar_bw_ul = json_utils::parseUint(json, "marBwUl");
  comp.mir_bw_dl = json_utils::parseUint(json, "mirBwDl");
  comp.mir_bw_ul = json_utils::parseUint(json, "mirBwUl");
  comp.codecs = json_utils::parseString(json, "codecs");
  comp.f_status = json_utils::parseInt(json, "fStatus");

  return comp;
}

// ============================================================================
// EventsSubscReqData
// ============================================================================

std::string EventsSubscReqData::toJson() const {
  std::ostringstream oss;
  oss << "{";

  if (!events.empty()) {
    oss << "\"events\": [";
    for (size_t i = 0; i < events.size(); ++i) {
      if (i > 0) oss << ", ";
      oss << "\"" << json_utils::escapeJson(events[i]) << "\"";
    }
    oss << "]";
  }

  if (notif_uri) {
    if (!events.empty()) oss << ", ";
    oss << json_utils::writeString("notifUri", *notif_uri);
  }

  if (notif_id) {
    if (!events.empty() || notif_uri) oss << ", ";
    oss << json_utils::writeString("notifId", *notif_id);
  }

  oss << "}";
  return oss.str();
}

// ============================================================================
// AppSessionContextReqData
// ============================================================================

std::string AppSessionContextReqData::toJson() const {
  std::ostringstream oss;
  oss << "{";

  bool first = true;

  auto writeField = [&](const std::string& field) -> std::ostringstream& {
    if (!first) oss << ", ";
    first = false;
    return oss;
  };

  writeField("") << json_utils::writeString("afAppId", af_app_id);
  writeField("") << json_utils::writeString("afChargId", af_charg_id);
  writeField("") << json_utils::writeString("afReqId", af_req_id);

  if (ue_ipv4) {
    writeField("") << json_utils::writeString("ueIpv4Addr", *ue_ipv4);
  }
  if (ue_ipv6) {
    writeField("") << json_utils::writeString("ueIpv6Prefix", *ue_ipv6);
  }
  if (serv_inf_status) {
    writeField("") << json_utils::writeInt("servInfStatus", static_cast<int>(*serv_inf_status));
  }
  if (sip_fork_ind) {
    writeField("") << json_utils::writeInt("sipForkInd", static_cast<int>(*sip_fork_ind));
  }
  if (dnn) {
    writeField("") << json_utils::writeString("dnn", *dnn);
  }
  if (supi) {
    writeField("") << json_utils::writeString("supi", *supi);
  }

  if (!med_components.empty()) {
    writeField("") << "\"medComponents\": [";
    for (size_t i = 0; i < med_components.size(); ++i) {
      if (i > 0) oss << ", ";
      oss << med_components[i].toJson();
    }
    oss << "]";
  }

  if (ev_subsc) {
    writeField("") << "\"evSubsc\": " << ev_subsc->toJson();
  }

  oss << "}";
  return oss.str();
}

std::optional<AppSessionContextReqData> AppSessionContextReqData::fromJson(const std::string& json) {
  AppSessionContextReqData req;

  req.af_app_id = json_utils::parseString(json, "afAppId").value_or("");
  req.af_charg_id = json_utils::parseString(json, "afChargId").value_or("");
  req.af_req_id = json_utils::parseString(json, "afReqId").value_or("");

  req.ue_ipv4 = json_utils::parseString(json, "ueIpv4Addr");
  req.ue_ipv6 = json_utils::parseString(json, "ueIpv6Prefix");

  auto status = json_utils::parseInt(json, "servInfStatus");
  if (status) {
    req.serv_inf_status = static_cast<ServiceInfoStatus>(*status);
  }

  return req;
}

// ============================================================================
// AppSessionContext
// ============================================================================

std::string AppSessionContext::toJson() const {
  std::ostringstream oss;
  oss << "{";

  if (app_session_id) {
    oss << json_utils::writeString("appSessionId", *app_session_id) << ", ";
  }

  oss << "\"ascReqData\": " << asc_req_data.toJson();
  oss << "}";
  return oss.str();
}

std::optional<AppSessionContext> AppSessionContext::fromJson(const std::string& json) {
  AppSessionContext ctx;

  ctx.app_session_id = json_utils::parseString(json, "appSessionId");

  // Extract ascReqData object
  std::regex req_re("\"ascReqData\"\\s*:\\s*\\{");
  std::smatch match;
  if (std::regex_search(json, match, req_re)) {
    // Find matching brace
    size_t start = match[0].second - json.begin();
    int brace_count = 1;
    size_t end = start;
    while (end < json.size() && brace_count > 0) {
      if (json[end] == '{') brace_count++;
      else if (json[end] == '}') brace_count--;
      end++;
    }

    std::string req_json = json.substr(start - 1, end - start + 1);
    auto req = AppSessionContextReqData::fromJson(req_json);
    if (!req) return std::nullopt;
    ctx.asc_req_data = *req;
  }

  return ctx;
}

// ============================================================================
// AppSessionContextUpdateData
// ============================================================================

std::string AppSessionContextUpdateData::toJson() const {
  std::ostringstream oss;
  oss << "{";

  bool first = true;

  if (af_app_id) {
    oss << json_utils::writeString("afAppId", *af_app_id);
    first = false;
  }
  if (af_charg_id) {
    if (!first) oss << ", ";
    oss << json_utils::writeString("afChargId", *af_charg_id);
    first = false;
  }
  if (af_req_id) {
    if (!first) oss << ", ";
    oss << json_utils::writeString("afReqId", *af_req_id);
    first = false;
  }
  if (serv_inf_status) {
    if (!first) oss << ", ";
    oss << json_utils::writeInt("servInfStatus", static_cast<int>(*serv_inf_status));
    first = false;
  }
  if (sip_fork_ind) {
    if (!first) oss << ", ";
    oss << json_utils::writeInt("sipForkInd", static_cast<int>(*sip_fork_ind));
    first = false;
  }

  if (!med_components.empty()) {
    if (!first) oss << ", ";
    oss << "\"medComponents\": [";
    for (size_t i = 0; i < med_components.size(); ++i) {
      if (i > 0) oss << ", ";
      oss << med_components[i].toJson();
    }
    oss << "]";
    first = false;
  }

  if (ev_subsc) {
    if (!first) oss << ", ";
    oss << "\"evSubsc\": " << ev_subsc->toJson();
  }

  oss << "}";
  return oss.str();
}

// ============================================================================
// EventsNotification
// ============================================================================

std::optional<EventsNotification> EventsNotification::fromJson(const std::string& json) {
  EventsNotification notif;

  notif.app_session_id = json_utils::parseString(json, "appSessionId").value_or("");
  notif.cause = json_utils::parseString(json, "cause");

  // Parse events array (simplified)
  std::regex events_re("\"events\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch match;
  if (std::regex_search(json, match, events_re) && match.size() > 1) {
    std::string events_str = match[1].str();
    std::regex str_re("\"([^\"]+)\"");
    std::sregex_iterator it(events_str.begin(), events_str.end(), str_re);
    std::sregex_iterator end;
    while (it != end) {
      notif.events.push_back((*it)[1].str());
      ++it;
    }
  }

  return notif;
}

// ============================================================================
// PolicyDecision
// ============================================================================

std::optional<PolicyDecision> PolicyDecision::fromJson(const std::string& json) {
  PolicyDecision decision;

  decision.app_session_id = json_utils::parseString(json, "appSessionId").value_or("");

  // Parse authorizedQos array (simplified)
  std::regex qos_re("\"authorizedQos\"\\s*:\\s*\\[([^\\]]*)\\]");
  std::smatch match;
  if (std::regex_search(json, match, qos_re) && match.size() > 1) {
    std::string qos_str = match[1].str();
    std::regex str_re("\"([^\"]+)\"");
    std::sregex_iterator it(qos_str.begin(), qos_str.end(), str_re);
    std::sregex_iterator end;
    while (it != end) {
      decision.authorized_qo_s.push_back((*it)[1].str());
      ++it;
    }
  }

  return decision;
}

// ============================================================================
// TerminationInfo
// ============================================================================

std::string TerminationInfo::toJson() const {
  std::ostringstream oss;
  oss << "{";
  oss << json_utils::writeString("appSessionId", app_session_id);
  oss << ", " << json_utils::writeInt("termCause", static_cast<int>(term_cause));
  if (resource_uri) {
    oss << ", " << json_utils::writeString("resourceUri", *resource_uri);
  }
  oss << "}";
  return oss.str();
}

} // namespace ims::n5
