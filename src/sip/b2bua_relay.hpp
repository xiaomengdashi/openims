#pragma once

#include "src/sip/sip_message.hpp"
#include "src/sip/sip_stack.hpp"

#include <string>
#include <unordered_map>

namespace ims::sip {

struct B2buaRelayConfig {
  std::string realm{"ims.local"};
  // next hop as SIP URI (used as Route)
  std::string next_hop_uri;
};

// Minimal SIP B2BUA relay:
// - inbound request -> create new out-of-dialog request to next hop
// - downstream response -> send corresponding response upstream (using stored upstream tid)
class B2buaRelay {
public:
  B2buaRelay(SipStack& sip, B2buaRelayConfig cfg);

  void on_message(const SipMessage& msg);

private:
  void on_request(const SipMessage& msg);
  void on_response(const SipMessage& msg);

  static std::string method_to_string(Method m);

  struct Leg {
    int upstream_tid{0};
    Method upstream_method{Method::Unknown};
  };

  SipStack& sip_;
  B2buaRelayConfig cfg_;
  std::unordered_map<int, Leg> downstream_tid_to_leg_;
};

} // namespace ims::sip

