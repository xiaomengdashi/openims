#pragma once

#include <string>
#include <unordered_map>

namespace ims::scscf {

enum class CallState { Idle, Offering, Established, Terminating };

struct CallSession {
  std::string call_id;
  std::string from_aor;
  std::string to_aor;
  int in_tid{0};   // UEa -> IMS transaction id
  int out_tid_2xx{0}; // 被叫侧 200 OK 的 tid（用于 ACK）
  int out_did{0};  // IMS -> UEb dialog id
  CallState state{CallState::Idle};
};

} // namespace ims::scscf

