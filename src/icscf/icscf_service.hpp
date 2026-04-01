#pragma once

#include <memory>
#include <string>

namespace ims::sip {
class SipStack;
struct SipMessage;
} // namespace ims::sip

namespace ims::scscf {
class ScscfService;
} // namespace ims::scscf

namespace ims::cx {
class ICxClient;
} // namespace ims::cx

namespace ims::dns {
class DnsResolver;
} // namespace ims::dns

namespace ims::icscf {

struct IcscfConfig {
  // 可选：如果 S-CSCF 不在同一进程，可配置其 SIP URI 用于转发
  // 例如 "sip:scscf.ims.local:6060;transport=udp"
  std::string scscf_sip_uri{};
};

// I-CSCF：入域路由与 S-CSCF 选择（MVP：配置驱动；后续可扩展 Diameter Cx/UDM 选择）
class IcscfService {
public:
  IcscfService(ims::sip::SipStack& sip, ims::scscf::ScscfService& scscf,
               ims::cx::ICxClient& cx, ims::dns::DnsResolver* dns, IcscfConfig cfg);

  void on_sip_message(const ims::sip::SipMessage& msg);

private:
  ims::sip::SipStack& sip_;
  ims::scscf::ScscfService& scscf_;
  ims::cx::ICxClient& cx_;
  ims::dns::DnsResolver* dns_;
  IcscfConfig cfg_;
};

} // namespace ims::icscf

