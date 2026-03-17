#pragma once

#include "ims/auth/auth_provider.hpp"
#include "ims/scscf/registration_sm.hpp"
#include "ims/storage/location_service.hpp"

#include <string>

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

namespace ims::scscf {

class ScscfService {
public:
  ScscfService(ims::sip::SipStack& sip,
              ims::auth::IAuthProvider& auth,
              ims::storage::LocationService& location,
              ims::media::RtpEngineClient& rtpengine,
              ims::media::SdpRewriter& sdp_rewriter,
              std::string realm,
              ims::policy::QosHook* qos_hook = nullptr);

  void on_sip_message(const ims::sip::SipMessage& msg);

private:
  void handle_register(const ims::sip::SipMessage& msg);
  void handle_invite(const ims::sip::SipMessage& msg);
  void handle_bye(const ims::sip::SipMessage& msg);

  ims::sip::SipStack& sip_;
  ims::auth::IAuthProvider& auth_;
  ims::storage::LocationService& location_;
  ims::media::RtpEngineClient& rtpengine_;
  ims::media::SdpRewriter& sdp_rewriter_;
  std::string realm_;
  ims::policy::QosHook* qos_hook_{nullptr};
};

} // namespace ims::scscf

