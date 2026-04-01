#include "src/scscf/registration_sm.hpp"

namespace ims::scscf {

RegistrationStateMachine::RegistrationStateMachine(ims::auth::IAuthProvider& auth, std::string realm)
    : auth_(auth), realm_(std::move(realm)) {}

RegisterDecision RegistrationStateMachine::on_register(RegistrationContext& ctx, const RegisterRequestView& req) {
  ctx.aor = req.aor;
  ctx.contact = req.contact;
  ctx.realm = realm_;

  if (req.authorization.empty()) {
    auto ch = auth_.getChallenge(ims::auth::AuthRequest{.impi = req.aor, .realm = realm_});
    if (!ch) return RegisterDecision{.action = RegisterDecision::Action::Reject};
    ctx.last_nonce = ch->nonce;
    ctx.state = RegistrationState::Challenged;
    return RegisterDecision{.action = RegisterDecision::Action::Send401, .www_authenticate = ch->www_authenticate};
  }

  const bool ok = auth_.verifyResponse(
      ims::auth::AuthResponse{.impi = req.aor, .realm = realm_, .method = req.method, .authorization_header = req.authorization});
  if (!ok) return RegisterDecision{.action = RegisterDecision::Action::Reject};
  ctx.state = RegistrationState::Registered;
  return RegisterDecision{.action = RegisterDecision::Action::Send200};
}

} // namespace ims::scscf

