#pragma once

#include "src/auth/auth_provider.hpp"
#include "src/storage/subscription_service.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace ims::scscf {

enum class SubscriptionState { Init, Challenged, Active, Terminated };

struct SubscriptionContext {
  std::string subscriber_aor;
  std::string notifier_aor;
  std::string realm;
  storage::EventPackage package;
  std::string contact;
  std::string last_nonce;
  std::chrono::seconds ttl{3600};
  SubscriptionState state{SubscriptionState::Init};
};

struct SubscribeRequestView {
  std::string from;        // Subscriber AOR
  std::string to;          // Notifier AOR
  std::string contact;     // Subscriber contact
  std::string authorization;
  std::string event;       // Event header value
  int expires;             // Expires value in seconds
  std::string call_id;
  std::string from_tag;
  std::string to_tag;
  uint32_t cseq;
};

struct SubscribeDecision {
  enum class Action { Send401, Send200, Reject };
  Action action{Action::Reject};
  std::string www_authenticate;
  int reply_expires{0};
};

class SubscriptionStateMachine {
public:
  explicit SubscriptionStateMachine(ims::auth::IAuthProvider& auth, std::string realm);
  SubscribeDecision on_subscribe(SubscriptionContext& ctx, const SubscribeRequestView& req);

private:
  ims::auth::IAuthProvider& auth_;
  std::string realm_;
};

} // namespace ims::scscf
