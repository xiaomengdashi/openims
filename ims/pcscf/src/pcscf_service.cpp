#include "ims/pcscf/pcscf_service.hpp"

#include "ims/icscf/icscf_service.hpp"
#include "ims/sip/sip_message.hpp"

namespace ims::pcscf {

PcscfService::PcscfService(ims::sip::SipStack& sip, ims::icscf::IcscfService& icscf) : sip_(sip), icscf_(icscf) {}

void PcscfService::on_sip_message(const ims::sip::SipMessage& msg) {
  // MVP：P-CSCF 只做入口转发与最小合法性校验，实际可补 Path/keepalive/topology hiding
  icscf_.on_sip_message(msg);
}

} // namespace ims::pcscf

