#pragma once

#include <string>

namespace ims::policy {

struct QosHookConfig {
  bool enabled{false};
  std::string http_url{};
  int http_timeout_ms{1500};
};

enum class SessionEventType { Setup, Established, Teardown };

struct SessionEvent {
  SessionEventType type{SessionEventType::Setup};
  std::string call_id;
  std::string from;
  std::string to;
};

class QosHook {
public:
  explicit QosHook(QosHookConfig cfg);
  void emit(const SessionEvent& ev) const;

private:
  QosHookConfig cfg_;
};

} // namespace ims::policy

