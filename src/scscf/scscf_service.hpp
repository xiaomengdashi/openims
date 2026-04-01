#pragma once

#include "src/auth/auth_provider.hpp"
#include "src/scscf/registration_sm.hpp"
#include "src/scscf/subscription_sm.hpp"
#include "src/storage/location_service.hpp"
#include "src/storage/subscription_service.hpp"

#include <string>
#include <unordered_map>

namespace ims::sip {
class SipStack;
struct SipMessage;
} // namespace ims::sip

namespace ims::media {
class RtpEngineClient;
class SdpRewriter;
} // namespace ims::media

namespace ims::policy {
class QosHook;
}

namespace ims::cx {
class ICxClient;
} // namespace ims::cx

namespace ims::scscf {

class ScscfService {
public:
  ScscfService(ims::sip::SipStack& sip,
              ims::auth::IAuthProvider& auth,
              ims::cx::ICxClient& cx,
              ims::storage::LocationService& location,
              ims::storage::SubscriptionService& subscriptions,
              ims::media::RtpEngineClient& rtpengine,
              ims::media::SdpRewriter& sdp_rewriter,
              std::string realm,
              ims::policy::QosHook* qos_hook = nullptr);

  void on_sip_message(const ims::sip::SipMessage& msg);

private:
  void handle_register(const ims::sip::SipMessage& msg);
  void handle_invite(const ims::sip::SipMessage& msg);
  void handle_bye(const ims::sip::SipMessage& msg);
  void handle_subscribe(const ims::sip::SipMessage& msg);
  void handle_notify(const ims::sip::SipMessage& msg);

  // Send NOTIFY notifications for registration state changes
  void notify_registration_change(const std::string& aor, bool active);

  // Send NOTIFY to a single subscriber
  void send_notify(storage::Subscription& sub, bool active);

  // Parse tags from From/To headers (extract tag parameter)
  static std::string parse_tag(const std::string& header);

  ims::sip::SipStack& sip_;
  ims::auth::IAuthProvider& auth_;
  ims::cx::ICxClient& cx_;
  ims::storage::LocationService& location_;
  ims::storage::SubscriptionService& subscriptions_;
  ims::media::RtpEngineClient& rtpengine_;
  ims::media::SdpRewriter& sdp_rewriter_;
  std::string realm_;
  ims::policy::QosHook* qos_hook_{nullptr};

  // Per-subscription context for authentication challenge
  std::unordered_map<std::string, SubscriptionContext> pending_subscriptions_;
};

} // namespace ims::scscf

