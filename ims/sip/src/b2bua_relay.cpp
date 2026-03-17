#include "ims/sip/b2bua_relay.hpp"

#include "ims/core/log.hpp"

namespace ims::sip {

B2buaRelay::B2buaRelay(SipStack& sip, B2buaRelayConfig cfg) : sip_(sip), cfg_(std::move(cfg)) {}

std::string B2buaRelay::method_to_string(Method m) {
  switch (m) {
    case Method::Register:
      return "REGISTER";
    case Method::Invite:
      return "INVITE";
    case Method::Ack:
      return "ACK";
    case Method::Bye:
      return "BYE";
    default:
      return "MESSAGE";
  }
}

void B2buaRelay::on_message(const SipMessage& msg) {
  if (msg.start.is_request) on_request(msg);
  else on_response(msg);
}

void B2buaRelay::on_request(const SipMessage& msg) {
  if (cfg_.next_hop_uri.empty()) {
    ims::core::log()->warn("B2buaRelay: next_hop_uri empty, dropping request call-id={}", msg.call_id);
    return;
  }

  OutOfDialogRequest out{};
  out.method = method_to_string(msg.start.method);

  // Keep logical To/From as AoR; send to next hop via Route.
  const std::string to_user = msg.to.empty() ? msg.from : msg.to;
  const std::string from_user = msg.from.empty() ? "unknown" : msg.from;
  out.to_uri = "sip:" + to_user + "@" + cfg_.realm;
  out.from_uri = "sip:" + from_user + "@" + cfg_.realm;
  out.route_uri = cfg_.next_hop_uri;
  out.call_id = msg.call_id;
  out.body = msg.body;
  out.content_type = msg.content_type.empty() ? "application/sdp" : msg.content_type;

  // Minimal header carry-over for REGISTER/auth
  if (!msg.authorization.empty()) out.headers["Authorization"] = msg.authorization;
  if (!msg.contact.empty()) out.headers["Contact"] = msg.contact;

  int downstream_tid = 0;
  if (!sip_.send_out_of_dialog(out, downstream_tid)) {
    ims::core::log()->warn("B2buaRelay: send_out_of_dialog failed call-id={}", msg.call_id);
    sip_.send_response_with_body(msg, 503, "", "text/plain");
    return;
  }
  downstream_tid_to_leg_[downstream_tid] = Leg{.upstream_tid = msg.tid, .upstream_method = msg.start.method};
}

void B2buaRelay::on_response(const SipMessage& msg) {
  auto it = downstream_tid_to_leg_.find(msg.tid);
  if (it == downstream_tid_to_leg_.end()) return;
  const auto leg = it->second;

  SipMessage upstream_req = msg;
  upstream_req.tid = leg.upstream_tid;

  // REGISTER 200 should include Contact if present
  if (leg.upstream_method == Method::Register && msg.start.status_code == 200) {
    sip_.send_response_200_simple(upstream_req, msg.contact, "", "text/plain");
  } else {
    sip_.send_response_with_body(upstream_req, msg.start.status_code, msg.body, msg.content_type.empty() ? "application/sdp" : msg.content_type);
  }

  if (msg.start.status_code >= 200) downstream_tid_to_leg_.erase(it);
}

} // namespace ims::sip

