#pragma once

#include <string>

namespace ims::sip {
class SipStack;
struct SipMessage;
} // namespace ims::sip

namespace ims::scscf {
class ScscfService;
} // namespace ims::scscf

namespace ims::icscf {
class IcscfService;
} // namespace ims::icscf

namespace ims::pcscf {

class PcscfService {
public:
  PcscfService(ims::sip::SipStack& sip, ims::icscf::IcscfService& icscf);
  void on_sip_message(const ims::sip::SipMessage& msg);

private:
  ims::sip::SipStack& sip_;
  ims::icscf::IcscfService& icscf_;
};

} // namespace ims::pcscf

