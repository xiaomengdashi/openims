#include "src/pcscf/pcscf_service.hpp"

#include "src/icscf/icscf_service.hpp"
#include "src/sip/sip_message.hpp"

#ifdef IMS_HAS_NGHTTP2
#include "src/n5/n5_client.hpp"
#include "src/n5/qos_policy.hpp"
#include "src/sip/pani_parser.hpp"
#endif

#include <spdlog/spdlog.h>

#include <unordered_map>

namespace ims::pcscf {

PcscfService::PcscfService(ims::sip::SipStack& sip, ims::icscf::IcscfService& icscf)
    : sip_(sip), icscf_(icscf) {}

PcscfService::~PcscfService() = default;

void PcscfService::set_n5_client(std::unique_ptr<ims::n5::IN5Client> n5_client) {
  n5_client_ = std::move(n5_client);
  if (n5_client_) {
    n5_client_->initialize();
    spdlog::info("[P-CSCF] N5 client initialized");
  }
}

void PcscfService::on_sip_message(const ims::sip::SipMessage& msg) {
#ifdef IMS_HAS_NGHTTP2
  // 5G VoNR: Extract P-Access-Network-Info for PDU Session info
  if (n5_client_ && msg.start.method == ims::sip::Method::Invite) {
    // Parse PANI header if present
    std::optional<ims::sip::AccessNetworkInfo> access_info;
    auto pani = msg.get_header("P-Access-Network-Info");
    if (pani && !pani->empty()) {
      access_info = ims::sip::parsePani(*pani);
      if (access_info) {
        spdlog::debug("[P-CSCF] 5G Access: {} (PDU Session: {}, DNN: {})",
                      ims::sip::getAccessTechnologyName(*access_info),
                      access_info->pdu_session_id.value_or("N/A"),
                      access_info->dnn.value_or("N/A"));
      }
    }

    // Create N5 session for QoS policy (simplified for MVP)
    // In full implementation, this would extract media components from SDP
    if (access_info && ims::sip::is5GNR(*access_info)) {
      spdlog::info("[P-CSCF] 5G NR detected for call {}, applying QoS policy", msg.call_id);

      // Build media components from SDP (simplified)
      std::vector<ims::n5::MediaComponent> media_components;

      // Extract media info from SDP (simplified - in real implementation parse SDP)
      if (!msg.body.empty()) {
        // Parse SDP to extract media types and ports
        // For MVP, we create default audio component
        ims::n5::MediaComponent audio_comp;
        audio_comp.med_com_id = 1;
        audio_comp.med_type = "AUDIO";
        audio_comp.med_com_status = 1;
        audio_comp.mar_bw_dl = n5_client_->getQosMapping().default_voice_bitrate_kbps;
        audio_comp.mar_bw_ul = n5_client_->getQosMapping().default_voice_bitrate_kbps;
        media_components.push_back(audio_comp);
      }

      // Build PDU Session info
      ims::n5::PduSessionInfo pdu_info;
      pdu_info.pdu_session_id = access_info->pdu_session_id.value_or("1");
      pdu_info.dnn = access_info->dnn.value_or("ims");
      if (access_info->snssai) {
        pdu_info.snssai.sd = access_info->snssai;
      }
      // Extract UE IP from SDP connection address (simplified)
      pdu_info.ue_ipv4 = "0.0.0.0";  // Would be extracted from SDP

      // Create N5 session
      auto result = n5_client_->createSession(
          msg.call_id,
          media_components,
          pdu_info);

      if (result.success) {
        spdlog::info("[P-CSCF] N5 session created: {} for call {}", result.resource_id, msg.call_id);
      } else {
        spdlog::warn("[P-CSCF] Failed to create N5 session: {}", result.error_message);
      }
    }
  }

  // Handle session termination (BYE)
  if (n5_client_ && msg.start.method == ims::sip::Method::Bye) {
    // In full implementation, we would track sessions and delete N5 session here
    spdlog::debug("[P-CSCF] BYE received for call {}", msg.call_id);
  }
#endif

  // Forward to I-CSCF
  icscf_.on_sip_message(msg);
}

} // namespace ims::pcscf

