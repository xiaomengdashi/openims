#include "ims/media/sdp_rewriter.hpp"

#include "ims/sip/sdp.hpp"

namespace ims::media {

std::string SdpRewriter::rewrite_offer(const std::string& sdp, const std::string& rtpengine_ip, int rtpengine_audio_port) const {
  return ims::sip::rewrite_sdp_connection_and_audio_port(sdp, rtpengine_ip, rtpengine_audio_port);
}

std::string SdpRewriter::rewrite_answer(const std::string& sdp, const std::string& rtpengine_ip, int rtpengine_audio_port) const {
  return ims::sip::rewrite_sdp_connection_and_audio_port(sdp, rtpengine_ip, rtpengine_audio_port);
}

} // namespace ims::media

