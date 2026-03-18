#include "ims/scscf/subscription_sm.hpp"

#include "ims/core/log.hpp"

namespace ims::scscf {

SubscriptionStateMachine::SubscriptionStateMachine(ims::auth::IAuthProvider& auth, std::string realm)
  : auth_(auth), realm_(std::move(realm)) {
}

SubscribeDecision SubscriptionStateMachine::on_subscribe(SubscriptionContext& ctx, const SubscribeRequestView& req) {
  ctx.subscriber_aor = req.from;
  ctx.notifier_aor = req.to;
  ctx.package = storage::parse_event_package(req.event);
  ctx.contact = req.contact;
  ctx.ttl = std::chrono::seconds{req.expires};
  ctx.realm = realm_;

  if (req.authorization.empty()) {
    auto ch = auth_.getChallenge(ims::auth::AuthRequest{.impi = req.from, .realm = realm_});
    if (!ch) return SubscribeDecision{.action = SubscribeDecision::Action::Reject};
    ctx.last_nonce = ch->nonce;
    ctx.state = SubscriptionState::Challenged;
    return SubscribeDecision{
      .action = SubscribeDecision::Action::Send401,
      .www_authenticate = ch->www_authenticate,
      .reply_expires = req.expires
    };
  }

  const bool ok = auth_.verifyResponse(
      ims::auth::AuthResponse{.impi = req.from, .realm = realm_, .method = "SUBSCRIBE", .authorization_header = req.authorization});
  if (!ok) {
    // Authentication failed - still send a new challenge
    auto ch = auth_.getChallenge(ims::auth::AuthRequest{.impi = req.from, .realm = realm_});
    if (!ch) return SubscribeDecision{.action = SubscribeDecision::Action::Reject};
    ctx.last_nonce = ch->nonce;
    ctx.state = SubscriptionState::Challenged;
    return SubscribeDecision{
      .action = SubscribeDecision::Action::Send401,
      .www_authenticate = ch->www_authenticate,
      .reply_expires = req.expires
    };
  }

  // Authentication successful
  ctx.state = SubscriptionState::Active;
  core::log()->info("SUBSCRIBE: Authentication succeeded for subscriber={} to notifier={}",
    ctx.subscriber_aor, ctx.notifier_aor);

  // If expires is 0, this is an unsubscribe
  if (req.expires == 0) {
    ctx.state = SubscriptionState::Terminated;
  }

  return SubscribeDecision{
    .action = SubscribeDecision::Action::Send200,
    .reply_expires = req.expires
  };
}

} // namespace ims::scscf
