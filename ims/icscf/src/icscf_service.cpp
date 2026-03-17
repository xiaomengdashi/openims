#include "ims/icscf/icscf_service.hpp"

#include "ims/core/log.hpp"
#include "ims/scscf/scscf_service.hpp"
#include "ims/sip/sip_message.hpp"
#include "ims/sip/sip_stack.hpp"

namespace ims::icscf {

IcscfService::IcscfService(ims::sip::SipStack& sip, ims::scscf::ScscfService& scscf, IcscfConfig cfg)
    : sip_(sip), scscf_(scscf), cfg_(std::move(cfg)) {}

void IcscfService::on_sip_message(const ims::sip::SipMessage& msg) {
  // MVP：I-CSCF 负责把外来请求路由到合适的 S-CSCF。
  // 目前项目内 S-CSCF 与 I-CSCF 同进程，直接调用即可。
  // 如果配置了 scscf_sip_uri，则可通过 SIP 转发（需要完整的代理/B2BUA 能力）。
  if (!cfg_.scscf_sip_uri.empty() && msg.start.is_request) {
    const bool ok = sip_.forward_request(msg, cfg_.scscf_sip_uri);
    if (!ok) ims::core::log()->warn("I-CSCF forward_request failed call-id={}", msg.call_id);
    return;
  }

  scscf_.on_sip_message(msg);
}

} // namespace ims::icscf

