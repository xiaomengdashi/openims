#include "src/sip/sip_stack.hpp"

#include "src/core/log.hpp"
#include "src/sip/sip_message.hpp"

#include <atomic>
#include <memory>

#include <netinet/in.h>
#include <unordered_set>

#if IMS_HAS_EXOSIP
#include <eXosip2/eXosip.h>
#include <osip2/osip_mt.h>
#include <osip2/osip.h>
#endif

namespace ims::sip {

struct SipStack::Impl {
  OnMessage on_message{};
#if IMS_HAS_EXOSIP
  eXosip_t* ctx{nullptr};
  std::atomic_bool running{false};
#endif
};

SipStack::SipStack() : impl_(new Impl()) {}

SipStack::~SipStack() {
#if IMS_HAS_EXOSIP
  if (impl_ && impl_->ctx) {
    eXosip_quit(impl_->ctx);
    impl_->ctx = nullptr;
  }
#endif
  delete impl_;
  impl_ = nullptr;
}

void SipStack::set_on_message(OnMessage cb) { impl_->on_message = std::move(cb); }

bool SipStack::start_udp(const std::string& bind_ip, int port) {
#if IMS_HAS_EXOSIP
  impl_->ctx = eXosip_malloc();
  if (!impl_->ctx) return false;
  if (eXosip_init(impl_->ctx) != 0) return false;
  if (eXosip_listen_addr(impl_->ctx, IPPROTO_UDP, bind_ip.c_str(), port, AF_INET, 0) != 0) return false;
  impl_->running = true;
  ims::core::log()->info("SIP stack listen UDP {}:{}", bind_ip, port);
  return true;
#else
  (void)bind_ip;
  (void)port;
  ims::core::log()->warn("SIP stack built without eXosip/osip; start_udp() is stub.");
  return false;
#endif
}

#if IMS_HAS_EXOSIP
static Method method_from_osip(osip_message_t* msg) {
  if (!msg || !msg->sip_method) return Method::Unknown;
  return parse_method(msg->sip_method);
}

static std::string hdr_value(osip_header_t* h) {
  if (!h || !h->hvalue) return {};
  return h->hvalue;
}

static SipMessage adapt_message(osip_message_t* msg) {
  SipMessage out;
  if (!msg) return out;

  if (MSG_IS_REQUEST(msg)) {
    out.start.is_request = true;
    out.start.method = method_from_osip(msg);
    if (msg->req_uri) {
      char* s = nullptr;
      if (osip_uri_to_str(msg->req_uri, &s) == 0 && s) {
        out.request_uri = s;
        osip_free(s);
      }
    }
  } else {
    out.start.is_request = false;
    out.start.status_code = msg->status_code;
    if (msg->reason_phrase) out.start.reason = msg->reason_phrase;
  }

  // raw SIP (best-effort; used for proxying when needed)
  {
    char* s = nullptr;
    std::size_t len = 0;
    if (osip_message_to_str(msg, &s, &len) == 0 && s) {
      out.raw.assign(s, s + len);
      osip_free(s);
    }
  }

  if (msg->call_id && msg->call_id->number) out.call_id = msg->call_id->number;

  if (msg->from && msg->from->url && msg->from->url->username) out.from = msg->from->url->username;
  if (msg->to && msg->to->url && msg->to->url->username) out.to = msg->to->url->username;

  if (msg->from) {
    char* s = nullptr;
    if (osip_from_to_str(msg->from, &s) == 0 && s) {
      out.from_hdr = s;
      osip_free(s);
    }
  }
  if (msg->to) {
    char* s = nullptr;
    if (osip_to_to_str(msg->to, &s) == 0 && s) {
      out.to_hdr = s;
      osip_free(s);
    }
  }

  if (msg->cseq && msg->cseq->number) out.cseq = msg->cseq->number;

  osip_header_t* h = nullptr;
  if (osip_message_header_get_byname(msg, "Contact", 0, &h) == 0) out.contact = hdr_value(h);
  h = nullptr;
  if (osip_message_header_get_byname(msg, "Authorization", 0, &h) == 0) out.authorization = hdr_value(h);
  h = nullptr;
  if (osip_message_header_get_byname(msg, "WWW-Authenticate", 0, &h) == 0) out.www_authenticate = hdr_value(h);
  h = nullptr;
  if (osip_message_header_get_byname(msg, "Content-Type", 0, &h) == 0) out.content_type = hdr_value(h);

  osip_body_t* body = nullptr;
  if (osip_message_get_body(msg, 0, &body) == 0) {
    if (body && body->body) out.body = body->body;
  }

  // Capture all headers in order (for proxying / header-chain logic)
  // Note: osip stores "unknown" headers in msg->headers; well-known headers may also appear there.
  for (int i = 0;; ++i) {
    osip_header_t* hh = nullptr;
    if (osip_message_get_header(msg, i, &hh) != 0 || !hh) break;
    SipHeader sh{};
    if (hh->hname) sh.name = hh->hname;
    if (hh->hvalue) sh.value = hh->hvalue;
    if (!sh.name.empty()) out.headers.push_back(std::move(sh));
  }

  return out;
}
#endif

void SipStack::poll_once(int timeout_ms) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx) return;
  eXosip_event_t* evt = eXosip_event_wait(impl_->ctx, timeout_ms, 50);
  eXosip_lock(impl_->ctx);
  eXosip_default_action(impl_->ctx, evt);
  eXosip_unlock(impl_->ctx);

  if (!evt) return;
  std::unique_ptr<eXosip_event_t, void (*)(eXosip_event_t*)> guard(evt, eXosip_event_free);
  if (evt->request) {
    auto m = adapt_message(evt->request);
    m.tid = evt->tid;
    m.did = evt->did;
    if (impl_->on_message) impl_->on_message(m);
    return;
  }
  if (evt->response) {
    auto m = adapt_message(evt->response);
    m.tid = evt->tid;
    m.did = evt->did;
    if (impl_->on_message) impl_->on_message(m);
    return;
  }
#else
  (void)timeout_ms;
#endif
}

bool SipStack::send_response_401(const SipMessage& req, const std::string& www_authenticate) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx || req.tid <= 0) return false;
  osip_message_t* answer = nullptr;
  if (eXosip_message_build_answer(impl_->ctx, req.tid, 401, &answer) != 0 || !answer) return false;
  osip_message_set_header(answer, "WWW-Authenticate", www_authenticate.c_str());
  eXosip_lock(impl_->ctx);
  const int rc = eXosip_message_send_answer(impl_->ctx, req.tid, 401, answer);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)req;
  (void)www_authenticate;
  return false;
#endif
}

bool SipStack::send_response_200_simple(const SipMessage& req, const std::string& contact, const std::string& body, const std::string& content_type) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx || req.tid <= 0) return false;
  osip_message_t* answer = nullptr;
  if (eXosip_message_build_answer(impl_->ctx, req.tid, 200, &answer) != 0 || !answer) return false;
  if (!contact.empty()) osip_message_set_header(answer, "Contact", contact.c_str());
  if (!body.empty()) {
    osip_message_set_body(answer, body.c_str(), static_cast<int>(body.size()));
    osip_message_set_content_type(answer, content_type.c_str());
  }
  eXosip_lock(impl_->ctx);
  const int rc = eXosip_message_send_answer(impl_->ctx, req.tid, 200, answer);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)req;
  (void)contact;
  (void)body;
  (void)content_type;
  return false;
#endif
}

bool SipStack::send_response_302(const SipMessage& req, const std::string& contact) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx || req.tid <= 0) return false;
  osip_message_t* answer = nullptr;
  if (eXosip_message_build_answer(impl_->ctx, req.tid, 302, &answer) != 0 || !answer) return false;
  if (!contact.empty()) osip_message_set_header(answer, "Contact", contact.c_str());
  eXosip_lock(impl_->ctx);
  const int rc = eXosip_message_send_answer(impl_->ctx, req.tid, 302, answer);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)req;
  (void)contact;
  return false;
#endif
}

bool SipStack::send_response_with_body(const SipMessage& req, int status_code, const std::string& body, const std::string& content_type) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx || req.tid <= 0) return false;
  osip_message_t* answer = nullptr;
  if (eXosip_message_build_answer(impl_->ctx, req.tid, status_code, &answer) != 0 || !answer) return false;
  if (!body.empty()) {
    osip_message_set_body(answer, body.c_str(), static_cast<int>(body.size()));
    osip_message_set_content_type(answer, content_type.c_str());
  }
  eXosip_lock(impl_->ctx);
  const int rc = eXosip_message_send_answer(impl_->ctx, req.tid, status_code, answer);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)req;
  (void)status_code;
  (void)body;
  (void)content_type;
  return false;
#endif
}

bool SipStack::send_invite(const std::string& from_uri,
                           const std::string& to_uri,
                           const std::string& request_uri,
                           const std::string& call_id,
                           const std::string& sdp_offer,
                           int& out_did) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx) return false;
  osip_message_t* invite = nullptr;
  // request-uri 指向 Contact；To/From 用 AOR
  const int rc0 = eXosip_call_build_initial_invite(impl_->ctx, &invite, to_uri.c_str(), from_uri.c_str(), request_uri.c_str(), "VoNR IMS call");
  if (rc0 != 0 || !invite) return false;

  if (!call_id.empty()) {
    osip_message_set_call_id(invite, call_id.c_str());
  }
  if (!sdp_offer.empty()) {
    osip_message_set_body(invite, sdp_offer.c_str(), static_cast<int>(sdp_offer.size()));
    osip_message_set_content_type(invite, "application/sdp");
  }

  eXosip_lock(impl_->ctx);
  const int did = eXosip_call_send_initial_invite(impl_->ctx, invite);
  eXosip_unlock(impl_->ctx);
  if (did <= 0) return false;
  out_did = did;
  return true;
#else
  (void)from_uri;
  (void)to_uri;
  (void)request_uri;
  (void)call_id;
  (void)sdp_offer;
  (void)out_did;
  return false;
#endif
}

bool SipStack::send_ack(int tid) {
#if IMS_HAS_EXOSIP
  // 注意：eXosip_call_build_ack / send_ack 使用的是 INVITE 2xx 的 transaction id(tid)，
  // 这里先保留接口但不在 MVP 中用于真机联调。
  if (!impl_->ctx || tid <= 0) return false;
  osip_message_t* ack = nullptr;
  eXosip_lock(impl_->ctx);
  const int rc0 = eXosip_call_build_ack(impl_->ctx, tid, &ack);
  if (rc0 != 0 || !ack) {
    eXosip_unlock(impl_->ctx);
    return false;
  }
  const int rc = eXosip_call_send_ack(impl_->ctx, tid, ack);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)tid;
  return false;
#endif
}

bool SipStack::send_bye(int did) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx || did <= 0) return false;
  osip_message_t* bye = nullptr;
  eXosip_lock(impl_->ctx);
  const int rc0 = eXosip_call_build_request(impl_->ctx, did, "BYE", &bye);
  if (rc0 != 0 || !bye) {
    eXosip_unlock(impl_->ctx);
    return false;
  }
  const int rc = eXosip_call_send_request(impl_->ctx, did, bye);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)did;
  return false;
#endif
}

bool SipStack::forward_request(const SipMessage& req, const std::string& target_uri) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx) return false;
  if (!req.start.is_request) return false;

  const char* method = "INVITE";
  switch (req.start.method) {
    case Method::Register:
      method = "REGISTER";
      break;
    case Method::Invite:
      method = "INVITE";
      break;
    case Method::Ack:
      method = "ACK";
      break;
    case Method::Bye:
      method = "BYE";
      break;
    case Method::Subscribe:
      method = "SUBSCRIBE";
      break;
    case Method::Notify:
      method = "NOTIFY";
      break;
    default:
      method = "INVITE";
      break;
  }

  // 注意：eXosip_message_build_request 需要 SIP URL（不是完整头域）。
  // 这里使用最小拼接，满足“可用但不完备”的转发能力。
  const std::string from_uri = req.from.empty() ? "sip:unknown@invalid" : ("sip:" + req.from);
  const std::string to_uri = target_uri;

  osip_message_t* out = nullptr;
  const int rc0 = eXosip_message_build_request(impl_->ctx, &out, method, to_uri.c_str(), from_uri.c_str(), nullptr);
  if (rc0 != 0 || !out) return false;

  if (!req.call_id.empty()) osip_message_set_call_id(out, req.call_id.c_str());
  if (!req.body.empty()) {
    osip_message_set_body(out, req.body.c_str(), static_cast<int>(req.body.size()));
    osip_message_set_content_type(out, req.content_type.empty() ? "application/sdp" : req.content_type.c_str());
  }

  eXosip_lock(impl_->ctx);
  const int rc = eXosip_message_send_request(impl_->ctx, out);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)req;
  (void)target_uri;
  return false;
#endif
}

bool SipStack::send_out_of_dialog(const OutOfDialogRequest& req, int& out_tid) {
#if IMS_HAS_EXOSIP
  out_tid = 0;
  if (!impl_->ctx) return false;
  if (req.method.empty() || req.to_uri.empty() || req.from_uri.empty()) return false;

  osip_message_t* out = nullptr;
  const char* route = req.route_uri.empty() ? nullptr : req.route_uri.c_str();
  const int rc0 = eXosip_message_build_request(impl_->ctx, &out, req.method.c_str(), req.to_uri.c_str(), req.from_uri.c_str(), route);
  if (rc0 != 0 || !out) return false;

  if (!req.call_id.empty()) osip_message_set_call_id(out, req.call_id.c_str());
  for (const auto& [k, v] : req.headers) {
    if (!k.empty() && !v.empty()) osip_message_set_header(out, k.c_str(), v.c_str());
  }
  if (!req.body.empty()) {
    osip_message_set_body(out, req.body.c_str(), static_cast<int>(req.body.size()));
    osip_message_set_content_type(out, req.content_type.empty() ? "application/sdp" : req.content_type.c_str());
  }

  eXosip_lock(impl_->ctx);
  const int tid = eXosip_message_send_request(impl_->ctx, out);
  eXosip_unlock(impl_->ctx);
  if (tid <= 0) return false;
  out_tid = tid;
  return true;
#else
  (void)req;
  (void)out_tid;
  return false;
#endif
}

bool SipStack::proxy_forward_raw(const SipMessage& inbound,
                                 const std::string& route_uri,
                                 const std::string& via_sent_by,
                                 const std::unordered_map<std::string, std::string>& add_headers,
                                 bool topology_hiding,
                                 int& out_tid) {
#if IMS_HAS_EXOSIP
  out_tid = 0;
  if (!impl_->ctx) return false;
  if (!inbound.start.is_request) return false;
  if (inbound.raw.empty()) return false;

  osip_message_t* msg = nullptr;
  if (osip_message_init(&msg) != 0 || !msg) return false;
  if (osip_message_parse(msg, inbound.raw.c_str(), static_cast<size_t>(inbound.raw.size())) != 0) {
    osip_message_free(msg);
    return false;
  }

  // Insert our Via at top (proxy behavior)
  if (!via_sent_by.empty()) {
    static std::atomic_uint64_t branch_ctr{1};
    const auto b = branch_ctr.fetch_add(1);
    const std::string via_val = "SIP/2.0/UDP " + via_sent_by + ";branch=z9hG4bKims-" + std::to_string(b) + ";rport";

    osip_via_t* v = nullptr;
    if (osip_via_init(&v) == 0 && v) {
      if (osip_via_parse(v, via_val.c_str()) == 0) {
        osip_list_add(&msg->vias, v, 0);
      } else {
        osip_via_free(v);
      }
    }
  }

  auto remove_all_headers_byname = [](osip_message_t* m, const char* name) {
    if (!m || !name) return;
    for (int i = 0; i < osip_list_size(&m->headers);) {
      osip_header_t* h = (osip_header_t*)osip_list_get(&m->headers, i);
      if (h && h->hname && osip_strcasecmp(h->hname, name) == 0) {
        osip_list_remove(&m->headers, i);
        osip_header_free(h);
        continue;
      }
      ++i;
    }
  };

  // Optionally strip topology-revealing headers (best-effort MVP)
  if (topology_hiding) {
    // Remove Route headers; proxy will steer using 'route_uri' next hop.
    while (osip_list_size(&msg->routes) > 0) {
      osip_route_t* r = (osip_route_t*)osip_list_get(&msg->routes, 0);
      osip_list_remove(&msg->routes, 0);
      osip_route_free(r);
    }
    // Remove existing Record-Route headers (keep only our own when added via add_headers)
    while (osip_list_size(&msg->record_routes) > 0) {
      osip_record_route_t* rr = (osip_record_route_t*)osip_list_get(&msg->record_routes, 0);
      osip_list_remove(&msg->record_routes, 0);
      osip_record_route_free(rr);
    }
    // Path is not exposed as a dedicated list in all libosip versions; remove via generic header list.
    remove_all_headers_byname(msg, "Path");
    remove_all_headers_byname(msg, "Route");
    remove_all_headers_byname(msg, "Record-Route");
  }

  // Apply explicit header additions/overrides
  for (const auto& [k, v] : add_headers) {
    if (!k.empty() && !v.empty()) osip_message_set_header(msg, k.c_str(), v.c_str());
  }

  // Set next hop Route if provided
  if (!route_uri.empty()) {
    osip_message_set_route(msg, route_uri.c_str());
  }

  eXosip_lock(impl_->ctx);
  const int tid = eXosip_message_send_request(impl_->ctx, msg);
  eXosip_unlock(impl_->ctx);
  if (tid <= 0) return false;
  out_tid = tid;
  return true;
#else
  (void)inbound;
  (void)route_uri;
  (void)add_headers;
  (void)topology_hiding;
  (void)out_tid;
  return false;
#endif
}

bool SipStack::proxy_relay_response(const SipMessage& upstream_req, const SipMessage& downstream_resp) {
#if IMS_HAS_EXOSIP
  if (!impl_->ctx || upstream_req.tid <= 0) return false;
  if (downstream_resp.start.is_request) return false;

  osip_message_t* answer = nullptr;
  const int code = downstream_resp.start.status_code;
  if (eXosip_message_build_answer(impl_->ctx, upstream_req.tid, code, &answer) != 0 || !answer) return false;

  // Copy a minimal but useful header set from downstream response.
  // (Do NOT copy Via; eXosip will build answer based on inbound transaction.)
  static const std::unordered_set<std::string> copy_hdrs = {
      "Contact",
      "Record-Route",
      "Service-Route",
      "P-Associated-URI",
      "P-Charging-Vector",
      "P-Charging-Function-Addresses",
      "Security-Server",
      "Security-Verify",
      "Supported",
      "Require",
  };

  for (const auto& h : downstream_resp.headers) {
    if (copy_hdrs.find(h.name) != copy_hdrs.end()) {
      if (!h.value.empty()) osip_message_set_header(answer, h.name.c_str(), h.value.c_str());
    }
  }

  if (!downstream_resp.body.empty()) {
    osip_message_set_body(answer, downstream_resp.body.c_str(), static_cast<int>(downstream_resp.body.size()));
    osip_message_set_content_type(answer, downstream_resp.content_type.empty() ? "application/sdp" : downstream_resp.content_type.c_str());
  }

  eXosip_lock(impl_->ctx);
  const int rc = eXosip_message_send_answer(impl_->ctx, upstream_req.tid, code, answer);
  eXosip_unlock(impl_->ctx);
  return rc == 0;
#else
  (void)upstream_req;
  (void)downstream_resp;
  return false;
#endif
}

} // namespace ims::sip

