#include "ims/policy/qos_hook.hpp"

#include "ims/core/log.hpp"

#include <cstdlib>

namespace ims::policy {

static const char* event_type_str(SessionEventType t) {
  switch (t) {
    case SessionEventType::Setup:
      return "setup";
    case SessionEventType::Established:
      return "established";
    case SessionEventType::Teardown:
      return "teardown";
    default:
      return "unknown";
  }
}

static std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out += c;
        break;
    }
  }
  return out;
}

QosHook::QosHook(QosHookConfig cfg) : cfg_(std::move(cfg)) {}

void QosHook::emit(const SessionEvent& ev) const {
  if (!cfg_.enabled) return;
  if (cfg_.http_url.empty()) return;

  const std::string body = std::string("{") + "\"type\":\"" + event_type_str(ev.type) + "\"," + "\"call_id\":\"" + json_escape(ev.call_id) +
                           "\"," + "\"from\":\"" + json_escape(ev.from) + "\"," + "\"to\":\"" + json_escape(ev.to) + "\"}";

  // Real integration without new deps: call curl(1).
  // Note: this requires curl installed on the host.
  const std::string cmd =
      "curl -sS --max-time " + std::to_string(std::max(1, cfg_.http_timeout_ms / 1000)) +
      " -H 'Content-Type: application/json' -X POST --data '" + body + "' '" + cfg_.http_url + "' >/dev/null 2>&1";

  ims::core::log()->info("QoS hook emit type={} call-id={}", event_type_str(ev.type), ev.call_id);
  (void)std::system(cmd.c_str());
}

} // namespace ims::policy

