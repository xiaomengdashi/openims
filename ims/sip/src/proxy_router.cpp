#include "ims/sip/proxy_router.hpp"

#include "ims/core/log.hpp"
#include "ims/sip/sip_stack.hpp"

#include <algorithm>
#include <string_view>

namespace ims::sip {

static bool ieq(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    const auto ca = static_cast<unsigned char>(a[i]);
    const auto cb = static_cast<unsigned char>(b[i]);
    if (std::tolower(ca) != std::tolower(cb)) return false;
  }
  return true;
}

static std::string method_to_string(Method m) {
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

ProxyRouter::ProxyRouter(SipStack& sip, ProxyRouterConfig cfg) : sip_(sip), cfg_(std::move(cfg)) {}

void ProxyRouter::on_message(const SipMessage& msg) {
  if (msg.start.is_request) on_request(msg);
  else on_response(msg);
}

bool ProxyRouter::should_record_route(const SipMessage& req) const {
  // Basic: dialog creating & mid-dialog routing (INVITE/SUBSCRIBE/NOTIFY/etc.)
  // MVP only: INVITE
  return req.start.is_request && req.start.method == Method::Invite;
}

bool ProxyRouter::should_add_path(const SipMessage& req) const {
  return req.start.is_request && req.start.method == Method::Register;
}

void ProxyRouter::on_request(const SipMessage& req) {
  if (cfg_.upstream_route_uri.empty()) {
    ims::core::log()->warn("ProxyRouter: upstream_route_uri empty, dropping request call-id={}", req.call_id);
    return;
  }
  if (req.raw.empty()) {
    ims::core::log()->warn("ProxyRouter: raw SIP empty, cannot proxy call-id={}", req.call_id);
    sip_.send_response_with_body(req, 500, "", "text/plain");
    return;
  }

  OutOfDialogRequest out{};
  out.method = method_to_string(req.start.method);

  // Keep AoR in To/From; send toward core using Route; preserve Call-ID.
  const std::string to_user = req.to.empty() ? req.from : req.to;
  const std::string from_user = req.from.empty() ? "unknown" : req.from;
  out.to_uri = "sip:" + to_user + "@" + cfg_.realm;
  out.from_uri = "sip:" + from_user + "@" + cfg_.realm;
  out.route_uri = cfg_.upstream_route_uri;
  out.call_id = req.call_id;
  out.body = req.body;
  out.content_type = req.content_type.empty() ? "application/sdp" : req.content_type;

  // Carry over headers needed for auth/registration; others are reconstructed by SIP stack.
  if (!req.authorization.empty()) out.headers["Authorization"] = req.authorization;
  if (!req.contact.empty()) out.headers["Contact"] = req.contact;

  // P-CSCF basics: PANI/PVNI/PAI (best-effort; only add if missing)
  const auto has_hdr = [&](std::string_view name) -> bool {
    for (const auto& h : req.headers) {
      if (ieq(h.name, name)) return true;
    }
    return false;
  };
  if (cfg_.pani && !has_hdr("P-Access-Network-Info")) out.headers["P-Access-Network-Info"] = *cfg_.pani;
  if (cfg_.pvni && !has_hdr("P-Visited-Network-ID")) out.headers["P-Visited-Network-ID"] = *cfg_.pvni;
  if (cfg_.pai && !has_hdr("P-Asserted-Identity")) out.headers["P-Asserted-Identity"] = *cfg_.pai;

  // Record-Route / Path to stay on signaling path
  if (!cfg_.self_uri.empty()) {
    if (should_record_route(req)) out.headers["Record-Route"] = "<" + cfg_.self_uri + ">";
    if (should_add_path(req)) out.headers["Path"] = "<" + cfg_.self_uri + ">";
  }

  int downstream_tid = 0;
  if (!sip_.send_out_of_dialog(out, downstream_tid)) {
    ims::core::log()->warn("ProxyRouter: send_out_of_dialog failed call-id={}", req.call_id);
    sip_.send_response_with_body(req, 503, "", "text/plain");
    return;
  }
  downstream_tid_to_leg_[downstream_tid] = Leg{.upstream_tid = req.tid, .upstream_method = req.start.method};
}

void ProxyRouter::on_response(const SipMessage& resp) {
  auto it = downstream_tid_to_leg_.find(resp.tid);
  if (it == downstream_tid_to_leg_.end()) return;
  const auto leg = it->second;

  SipMessage upstream_req = resp;
  upstream_req.tid = leg.upstream_tid;

  // Relay status/body back to upstream transaction
  if (leg.upstream_method == Method::Register && resp.start.status_code == 200) {
    sip_.send_response_200_simple(upstream_req, resp.contact, "", "text/plain");
  } else {
    sip_.send_response_with_body(upstream_req, resp.start.status_code, resp.body, resp.content_type.empty() ? "application/sdp" : resp.content_type);
  }

  if (resp.start.status_code >= 200) downstream_tid_to_leg_.erase(it);
}

} // namespace ims::sip

