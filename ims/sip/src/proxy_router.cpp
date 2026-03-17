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

static std::string derive_via_sent_by(const ProxyRouterConfig& cfg) {
  if (!cfg.via_sent_by.empty()) return cfg.via_sent_by;
  // best-effort: parse "sip:host[:port];..." from self_uri
  // examples: sip:pcscf.ims.local:5060;transport=udp;lr
  const std::string& s = cfg.self_uri;
  const std::string prefix = "sip:";
  auto p = s.find(prefix);
  if (p == std::string::npos) return {};
  p += prefix.size();
  auto end = s.find_first_of(";>", p);
  const auto hostport = s.substr(p, end == std::string::npos ? std::string::npos : (end - p));
  return hostport;
}

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

  std::unordered_map<std::string, std::string> add_headers;
  // P-CSCF basics: PANI/PVNI/PAI (best-effort; only add if missing)
  const auto has_hdr = [&](std::string_view name) -> bool {
    for (const auto& h : req.headers) {
      if (ieq(h.name, name)) return true;
    }
    return false;
  };
  if (cfg_.pani && !has_hdr("P-Access-Network-Info")) add_headers["P-Access-Network-Info"] = *cfg_.pani;
  if (cfg_.pvni && !has_hdr("P-Visited-Network-ID")) add_headers["P-Visited-Network-ID"] = *cfg_.pvni;
  if (cfg_.pai && !has_hdr("P-Asserted-Identity")) add_headers["P-Asserted-Identity"] = *cfg_.pai;

  // Record-Route / Path to stay on signaling path
  if (!cfg_.self_uri.empty()) {
    if (should_record_route(req)) add_headers["Record-Route"] = "<" + cfg_.self_uri + ">";
    if (should_add_path(req)) add_headers["Path"] = "<" + cfg_.self_uri + ">";
  }

  int downstream_tid = 0;
  const auto via_sent_by = derive_via_sent_by(cfg_);
  if (!sip_.proxy_forward_raw(req, cfg_.upstream_route_uri, via_sent_by, add_headers, cfg_.topology_hiding, downstream_tid)) {
    ims::core::log()->warn("ProxyRouter: proxy_forward_raw failed call-id={}", req.call_id);
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

  // Relay response headers/body back to upstream transaction (proxy-style)
  sip_.proxy_relay_response(upstream_req, resp);

  if (resp.start.status_code >= 200) downstream_tid_to_leg_.erase(it);
}

} // namespace ims::sip

