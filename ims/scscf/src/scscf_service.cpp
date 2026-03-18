#include "ims/scscf/scscf_service.hpp"

#include "ims/core/log.hpp"
#include "ims/cx/cx_client.hpp"
#include "ims/media/rtpengine_client.hpp"
#include "ims/media/sdp_rewriter.hpp"
#include "ims/policy/qos_hook.hpp"
#include "ims/scscf/call_session.hpp"
#include "ims/sip/sip_message.hpp"
#include "ims/sip/sip_stack.hpp"

namespace ims::scscf {

static std::unordered_map<std::string, CallSession>& call_map() {
  static std::unordered_map<std::string, CallSession> calls;
  return calls;
}

ScscfService::ScscfService(ims::sip::SipStack& sip,
                           ims::auth::IAuthProvider& auth,
                           ims::cx::ICxClient& cx,
                           ims::storage::LocationService& location,
                           ims::storage::SubscriptionService& subscriptions,
                           ims::media::RtpEngineClient& rtpengine,
                           ims::media::SdpRewriter& sdp_rewriter,
                           std::string realm,
                           ims::policy::QosHook* qos_hook)
    : sip_(sip),
      auth_(auth),
      cx_(cx),
      location_(location),
      subscriptions_(subscriptions),
      rtpengine_(rtpengine),
      sdp_rewriter_(sdp_rewriter),
      realm_(std::move(realm)),
      qos_hook_(qos_hook) {}

void ScscfService::on_sip_message(const ims::sip::SipMessage& msg) {
  using ims::sip::Method;
  if (!msg.start.is_request) {
    // 最小 B2BUA：收到被叫侧 response 后，回到主叫侧事务
    auto& calls = call_map();
    auto it = calls.find(msg.call_id);
    if (it == calls.end()) return;
    auto& cs = it->second;

    // 仅处理对 INVITE 的 180/183/200
    if (msg.start.status_code >= 180 && msg.start.status_code < 300) {
      std::string body = msg.body;
      if (!body.empty()) {
        auto anchored = rtpengine_.answer(msg.call_id, msg.body);
        if (anchored) body = *anchored;
      }
      ims::sip::SipMessage fake_req = msg; // reuse tid from stored
      fake_req.tid = cs.in_tid;
      sip_.send_response_with_body(fake_req, msg.start.status_code, body, msg.content_type.empty() ? "application/sdp" : msg.content_type);
      if (msg.start.status_code == 200) {
        cs.state = CallState::Established;
        cs.out_tid_2xx = msg.tid;
        if (qos_hook_) {
          qos_hook_->emit(ims::policy::SessionEvent{.type = ims::policy::SessionEventType::Established, .call_id = msg.call_id, .from = cs.from_aor, .to = cs.to_aor});
        }
      }
    }
    return;
  }

  switch (msg.start.method) {
    case Method::Register:
      handle_register(msg);
      return;
    case Method::Invite:
      handle_invite(msg);
      return;
    case Method::Bye:
      handle_bye(msg);
      return;
    case Method::Subscribe:
      handle_subscribe(msg);
      return;
    case Method::Notify:
      handle_notify(msg);
      return;
    case Method::Ack: {
      auto& calls = call_map();
      auto it = calls.find(msg.call_id);
      if (it != calls.end() && it->second.out_did > 0) {
        // ACK 需要使用被叫侧 200OK 的 tid
        if (it->second.out_tid_2xx > 0) sip_.send_ack(it->second.out_tid_2xx);
      }
      return;
    }
    default:
      ims::core::log()->info("Unhandled SIP request method");
      return;
  }
}

void ScscfService::handle_register(const ims::sip::SipMessage& msg) {
  const std::string& impu = msg.from;
  if (!impu.empty()) {
    // Query Cx for user profile
    auto profile = cx_.getUserProfile(impu);
    if (!profile) {
      ims::core::log()->warn("S-CSCF: No user profile found in Cx for impu={}", impu);
      return;
    }
    ims::core::log()->debug("S-CSCF: Got user profile from Cx - impi={} impu={} registered={}",
                          profile->impi, profile->impu, profile->registered);
  }

  RegistrationContext ctx{};
  RegistrationStateMachine sm{auth_, realm_};

  RegisterRequestView req{
      .aor = msg.from.empty() ? "unknown" : msg.from,
      .contact = msg.contact,
      .authorization = msg.authorization,
      .method = "REGISTER",
  };

  auto decision = sm.on_register(ctx, req);
  if (decision.action == RegisterDecision::Action::Send401) {
    ims::core::log()->info("REGISTER 401 for aor={} call-id={}", ctx.aor, msg.call_id);
    sip_.send_response_401(msg, decision.www_authenticate);
    return;
  }
  if (decision.action == RegisterDecision::Action::Send200) {
    ims::core::log()->info("REGISTER 200 for aor={} contact={}", ctx.aor, ctx.contact);
    bool active = ctx.ttl.count() > 0;
    if (active) {
      location_.upsert(ctx.aor, ctx.contact, ctx.ttl);
    } else {
      location_.remove(ctx.aor);
    }

    // Notify Cx (HSS) of registration - SAR
    cx_.serverAssignment(msg.from, msg.from,
                        ims::cx::ICxClient::ServerAssignmentType::REGISTRATION);

    // Notify all reg-event subscribers of the registration state change
    notify_registration_change(ctx.aor, active);

    sip_.send_response_200_simple(msg, ctx.contact, "", "application/sdp");
    return;
  }

  ims::core::log()->warn("REGISTER rejected aor={} call-id={}", ctx.aor, msg.call_id);
}

void ScscfService::handle_invite(const ims::sip::SipMessage& msg) {
  const auto from = msg.from;
  const auto to = msg.to;
  ims::core::log()->info("INVITE from={} to={} call-id={}", from, to, msg.call_id);

  const auto binding = location_.lookup(to);
  if (!binding) {
    ims::core::log()->warn("INVITE no binding for to={}", to);
    return;
  }

  // B2BUA：IMS 发起到被叫的 INVITE，并把被叫 response 回给主叫
  auto& calls = call_map();
  CallSession cs{};
  cs.call_id = msg.call_id;
  cs.from_aor = from;
  cs.to_aor = to;
  cs.in_tid = msg.tid;
  cs.state = CallState::Offering;

  std::string offer_sdp = msg.body;
  if (!offer_sdp.empty()) {
    auto offer = rtpengine_.offer(msg.call_id, offer_sdp);
    if (!offer) {
      ims::core::log()->warn("RTPengine offer failed call-id={}", msg.call_id);
      sip_.send_response_with_body(msg, 488, "", "application/sdp");
      return;
    }
    offer_sdp = sdp_rewriter_.rewrite_offer(offer_sdp, offer->public_ip, offer->audio_port);
  }

  const std::string from_uri = "sip:" + from + "@" + realm_;
  const std::string to_uri = "sip:" + to + "@" + realm_;

  int out_did = 0;
  if (!sip_.send_invite(from_uri, to_uri, binding->contact, msg.call_id, offer_sdp, out_did)) {
    ims::core::log()->warn("send_invite failed call-id={}", msg.call_id);
    sip_.send_response_with_body(msg, 500, "", "application/sdp");
    return;
  }
  cs.out_did = out_did;
  calls[msg.call_id] = cs;

  if (qos_hook_) {
    qos_hook_->emit(ims::policy::SessionEvent{.type = ims::policy::SessionEventType::Setup, .call_id = msg.call_id, .from = from, .to = to});
  }
}

void ScscfService::handle_bye(const ims::sip::SipMessage& msg) {
  ims::core::log()->info("BYE call-id={}", msg.call_id);
  auto& calls = call_map();
  auto it = calls.find(msg.call_id);
  if (it != calls.end()) {
    if (it->second.out_did > 0) sip_.send_bye(it->second.out_did);
    calls.erase(it);
  }
  rtpengine_.remove(msg.call_id);

  if (qos_hook_) {
    qos_hook_->emit(ims::policy::SessionEvent{.type = ims::policy::SessionEventType::Teardown, .call_id = msg.call_id, .from = msg.from, .to = msg.to});
  }

  // Notify dialog-event subscribers that this dialog has terminated
  // (dialog-id is the call-id)
  auto subscriptions = subscriptions_.find_by_dialog(msg.call_id);
  for (auto& sub : subscriptions) {
    send_notify(sub, false);
    subscriptions_.remove(sub.subscription_id);
  }
}

// Parse tag parameter from From/To header (e.g. "sip:user@host;tag=abc123" -> "abc123")
std::string ScscfService::parse_tag(const std::string& header) {
  // Look for "tag=" parameter
  auto pos = header.find("tag=");
  if (pos == std::string::npos) {
    return "";
  }
  pos += 4;
  auto end = header.find_first_of("; \t>", pos);
  if (end == std::string::npos) {
    return header.substr(pos);
  }
  return header.substr(pos, end - pos);
}

void ScscfService::handle_subscribe(const ims::sip::SipMessage& msg) {
  ims::core::log()->info("SUBSCRIBE from={} to={} call-id={}", msg.from, msg.to, msg.call_id);

  // Parse required headers
  auto event_hdr = msg.get_header("Event");
  if (!event_hdr) {
    ims::core::log()->warn("SUBSCRIBE missing Event header call-id={}", msg.call_id);
    sip_.send_response_with_body(msg, 400, "Bad Request - missing Event header", "text/plain");
    return;
  }

  // Parse Expires header (default to 3600 seconds)
  int expires = 3600;
  auto expires_hdr = msg.get_header("Expires");
  if (expires_hdr) {
    expires = std::stoi(*expires_hdr);
  }

  // If expires=0, this is an unsubscribe
  if (expires == 0) {
    auto from_tag = parse_tag(msg.from_hdr);
    auto to_tag = parse_tag(msg.to_hdr);
    auto sid = storage::SubscriptionService::generate_subscription_id(msg.call_id, from_tag, to_tag);
    subscriptions_.remove(sid);
    ims::core::log()->info("SUBSCRIBE unsubscribe sid={}", sid);
    sip_.send_response_200_simple(msg, msg.contact, "", "text/plain");
    return;
  }

  // Get user profile from Cx
  const std::string& subscriber = msg.from;
  if (!subscriber.empty()) {
    auto profile = cx_.getUserProfile(subscriber);
    if (!profile) {
      ims::core::log()->warn("S-CSCF: No user profile found in Cx for subscriber={}", subscriber);
      sip_.send_response_with_body(msg, 404, "Not Found", "text/plain");
      return;
    }
  }

  // Parse tags for subscription ID
  auto from_tag = parse_tag(msg.from_hdr);
  auto to_tag = parse_tag(msg.to_hdr);

  // Create subscription context
  SubscriptionContext ctx{};
  SubscriptionStateMachine sm{auth_, realm_};

  uint32_t cseq = 0;
  if (!msg.cseq.empty()) {
    // Extract CSeq number from CSeq header (e.g. "123 INVITE" -> 123)
    auto space = msg.cseq.find(' ');
    if (space != std::string::npos) {
      cseq = static_cast<uint32_t>(std::stoul(msg.cseq.substr(0, space)));
    } else {
      cseq = static_cast<uint32_t>(std::stoul(msg.cseq));
    }
  }

  SubscribeRequestView req{
    .from = msg.from.empty() ? "unknown" : msg.from,
    .to = msg.to.empty() ? "unknown" : msg.to,
    .contact = msg.contact,
    .authorization = msg.authorization,
    .event = *event_hdr,
    .expires = expires,
    .call_id = msg.call_id,
    .from_tag = from_tag,
    .to_tag = to_tag,
    .cseq = cseq
  };

  auto decision = sm.on_subscribe(ctx, req);

  // Generate subscription ID for this subscription
  auto sid = storage::SubscriptionService::generate_subscription_id(
    msg.call_id, from_tag, to_tag);

  if (decision.action == SubscribeDecision::Action::Send401) {
    ims::core::log()->info("SUBSCRIBE 401 for subscriber={} notifier={} call-id={}",
      ctx.subscriber_aor, ctx.notifier_aor, msg.call_id);
    pending_subscriptions_[sid] = ctx;
    sip_.send_response_401(msg, decision.www_authenticate);
    return;
  }

  if (decision.action == SubscribeDecision::Action::Send200) {
    ims::core::log()->info("SUBSCRIBE 200 OK for subscriber={} notifier={} event={}",
      ctx.subscriber_aor, ctx.notifier_aor, event_hdr.value());

    // Check if this is a re-subscription to existing context
    auto it = pending_subscriptions_.find(sid);
    if (it != pending_subscriptions_.end()) {
      ctx = it->second;
      pending_subscriptions_.erase(it);
    }

    // Store the subscription
    std::string dialog_id = "";
    if (ctx.package == storage::EventPackage::DialogEvent) {
      // For dialog event, dialog-id is the call-id of the dialog being subscribed
      // In IMS this is typically carried in the Request-URI or Event header
      // For simplicity we use the notifier Aor pattern to extract call-id
      dialog_id = msg.to;
    }

    subscriptions_.upsert(
      ctx.package,
      ctx.notifier_aor,
      ctx.subscriber_aor,
      ctx.contact,
      msg.call_id,
      from_tag,
      to_tag,
      dialog_id,
      ctx.ttl,
      cseq
    );

    // Send 200 OK
    sip_.send_response_200_simple(msg, ctx.contact, "", "text/plain");

    // Send initial NOTIFY with current state
    if (ctx.package == storage::EventPackage::RegEvent) {
      // For reg-event, check if user is currently registered
      bool active = location_.lookup(ctx.notifier_aor).has_value();
      auto sub_opt = subscriptions_.lookup(sid);
      if (sub_opt) {
        send_notify(*sub_opt, active);
      }
    } else if (ctx.package == storage::EventPackage::DialogEvent) {
      // For dialog-event, check if dialog exists
      auto& calls = call_map();
      bool active = calls.find(dialog_id) != calls.end();
      auto sub_opt = subscriptions_.lookup(sid);
      if (sub_opt) {
        send_notify(*sub_opt, active);
      }
    }

    return;
  }

  ims::core::log()->warn("SUBSCRIBE rejected call-id={}", msg.call_id);
  sip_.send_response_with_body(msg, 403, "Forbidden", "text/plain");
}

void ScscfService::handle_notify(const ims::sip::SipMessage& msg) {
  // In S-CSCF acting as notifier, we only receive NOTIFY acks
  // Just log and acknowledge
  ims::core::log()->info("NOTIFY received call-id={}", msg.call_id);
  sip_.send_response_200_simple(msg, "", "", "text/plain");
}

void ScscfService::notify_registration_change(const std::string& aor, bool active) {
  auto subscriptions = subscriptions_.find_by_notifier(aor, storage::EventPackage::RegEvent);
  for (auto& sub : subscriptions) {
    send_notify(sub, active);
  }
}

void ScscfService::send_notify(storage::Subscription& sub, bool active) {
  // Build NOTIFY request
  std::string event_str = storage::event_package_to_string(sub.package);
  std::string state = active ? "active" : "terminated";

  // Generate simple XML body based on event type
  std::string body;
  std::string content_type;

  if (sub.package == storage::EventPackage::RegEvent) {
    // RFC 3680 reg-event minimal XML
    content_type = "application/reginfo+xml";
    body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\">\n"
            "  <registration aor=\"sip:" + sub.notifier_aor + "@" + realm_ + "\" state=\"" + state + "\"/>\n"
            "</reginfo>\n";
  } else if (sub.package == storage::EventPackage::DialogEvent) {
    // RFC 4235 dialog-event minimal XML
    content_type = "application/dialog-info+xml";
    body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"1\" state=\"" + state + "\"/>\n";
  } else {
    content_type = "text/plain";
    body = "Event: " + event_str + "\nState: " + state + "\n";
  }

  // Increment CSeq for NOTIFY
  uint32_t new_cseq = sub.last_cseq + 1;
  sub.last_cseq = new_cseq;

  // Send NOTIFY as out-of-dialog request to subscriber contact
  // The contact should already be a sip URI
  std::string from_uri = "sip:" + sub.notifier_aor + "@" + realm_;
  std::string to_uri = sub.subscriber_contact;

  ims::core::log()->info("Sending NOTIFY to {} event={} state={}",
    sub.subscriber_contact, event_str, state);

  ims::sip::OutOfDialogRequest req;
  req.method = "NOTIFY";
  req.from_uri = from_uri;
  req.to_uri = to_uri;
  req.call_id = sub.call_id;
  req.body = body;
  req.content_type = content_type;

  int out_tid = 0;
  sip_.send_out_of_dialog(req, out_tid);
}

} // namespace ims::scscf

