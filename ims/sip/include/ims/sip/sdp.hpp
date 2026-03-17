#pragma once

#include <optional>
#include <string>

namespace ims::sip {

struct SdpConnection {
  std::string address;
};

struct SdpMedia {
  std::string media; // audio/video
  int port{0};
  std::string proto; // RTP/AVP...
};

struct SdpSession {
  std::optional<SdpConnection> connection;
  std::optional<SdpMedia> audio;
};

SdpSession parse_sdp_minimal(const std::string& sdp);
std::string rewrite_sdp_connection_and_audio_port(const std::string& sdp, const std::string& new_ip, int new_audio_port);

} // namespace ims::sip

