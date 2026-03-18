#include "ims/icscf/icscf_service.hpp"

#include "ims/core/log.hpp"
#include "ims/dns/dns_resolver.hpp"
#include "ims/cx/cx_client.hpp"
#include "ims/scscf/scscf_service.hpp"
#include "ims/sip/sip_message.hpp"
#include "ims/sip/sip_stack.hpp"

namespace ims::icscf {

IcscfService::IcscfService(ims::sip::SipStack& sip, ims::scscf::ScscfService& scscf,
                             ims::cx::ICxClient& cx, ims::dns::DnsResolver* dns, IcscfConfig cfg)
    : sip_(sip), scscf_(scscf), cx_(cx), dns_(dns), cfg_(std::move(cfg)) {}

void IcscfService::on_sip_message(const ims::sip::SipMessage& msg) {
  // I-CSCF：入域路由与 S-CSCF 选择
  // - Query Cx (HSS) for S-CSCF capabilities during registration (UAR)
  // - Query Cx (HSS) for registered S-CSCF for terminating calls (LIR)
  // - MVP: Cx is stubbed with static config

  if (msg.start.is_request) {
    // For REGISTER requests, query Cx for S-CSCF capabilities
    if (msg.start.method == ims::sip::Method::Register) {
      // IMPU is in the From header
      const std::string& impu = msg.from;
      if (!impu.empty()) {
        // Query Cx for user authorization (UAR) - gets S-CSCF capabilities
        // MVP: Stub just returns default capabilities
        auto caps = cx_.userAuthorization(impu, "");
        if (caps) {
          ims::core::log()->debug("I-CSCF: Got S-CSCF capabilities from Cx for impu={}", impu);
        }
      }
    }

    // For terminating calls (non-REGISTER), query Cx for location info (LIR)
    if (msg.start.method != ims::sip::Method::Register) {
      // IMPU is in the Request-URI (To header for initial requests)
      const std::string& impu = msg.to;
      if (!impu.empty()) {
        // Query Cx for location information (LIR)
        auto scscf_uri = cx_.getLocation(impu);
        if (scscf_uri && !scscf_uri->empty()) {
          ims::core::log()->debug("I-CSCF: Got S-CSCF from Cx for impu={} scscf={}", impu, *scscf_uri);
          // Use the S-CSCF URI from HSS if available
          const bool ok = sip_.forward_request(msg, *scscf_uri);
          if (!ok) ims::core::log()->warn("I-CSCF forward_request (from Cx) failed call-id={}", msg.call_id);
          return;
        }
      }
    }
  }

  // MVP: If no dynamic routing from Cx, use static config or in-process call
  if (!cfg_.scscf_sip_uri.empty() && msg.start.is_request) {
    const bool ok = sip_.forward_request(msg, cfg_.scscf_sip_uri);
    if (!ok) ims::core::log()->warn("I-CSCF forward_request failed call-id={}", msg.call_id);
    return;
  }

  scscf_.on_sip_message(msg);
}

} // namespace ims::icscf

