#include "ims/scscf/scscf_service.hpp"

#include "ims/core/log.hpp"
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
                           ims::storage::LocationService& location,
                           ims::media::RtpEngineClient& rtpengine,
                           ims::media::SdpRewriter& sdp_rewriter,
                           std::string realm,
                           ims::policy::QosHook* qos_hook)
    : sip_(sip),
      auth_(auth),
      location_(location),
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
    location_.upsert(ctx.aor, ctx.contact, ctx.ttl);
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
}

} // namespace ims::scscf

