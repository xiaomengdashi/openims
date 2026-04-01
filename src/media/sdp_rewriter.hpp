#pragma once

#include <string>

namespace ims::media {

class SdpRewriter {
public:
  std::string rewrite_offer(const std::string& sdp, const std::string& rtpengine_ip, int rtpengine_audio_port) const;
  std::string rewrite_answer(const std::string& sdp, const std::string& rtpengine_ip, int rtpengine_audio_port) const;
};

} // namespace ims::media

