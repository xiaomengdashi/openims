#pragma once

#include "src/auth/auth_provider.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace ims::scscf {

enum class RegistrationState { Init, Challenged, Registered, Expired };

struct RegistrationContext {
  std::string aor;
  std::string contact;
  std::string realm;
  std::string last_nonce;
  std::chrono::seconds ttl{3600};
  RegistrationState state{RegistrationState::Init};
};

struct RegisterRequestView {
  std::string aor;
  std::string contact;
  std::string authorization;
  std::string method; // "REGISTER"
};

struct RegisterDecision {
  enum class Action { Send401, Send200, Reject };
  Action action{Action::Reject};
  std::string www_authenticate;
};

class RegistrationStateMachine {
public:
  explicit RegistrationStateMachine(ims::auth::IAuthProvider& auth, std::string realm);
  RegisterDecision on_register(RegistrationContext& ctx, const RegisterRequestView& req);

private:
  ims::auth::IAuthProvider& auth_;
  std::string realm_;
};

} // namespace ims::scscf

