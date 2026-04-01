#include "src/sip/sdp.hpp"

#include <sstream>

namespace ims::sip {

static bool starts_with(const std::string& s, const std::string& pfx) { return s.rfind(pfx, 0) == 0; }

SdpSession parse_sdp_minimal(const std::string& sdp) {
  SdpSession out;
  std::istringstream iss(sdp);
  std::string line;
  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (starts_with(line, "c=")) {
      // c=IN IP4 1.2.3.4
      auto pos = line.find_last_of(' ');
      if (pos != std::string::npos && pos + 1 < line.size()) out.connection = SdpConnection{line.substr(pos + 1)};
    } else if (starts_with(line, "m=audio")) {
      // m=audio 49170 RTP/AVP 0 8 96
      std::istringstream ls(line.substr(2));
      SdpMedia m{};
      ls >> m.media >> m.port >> m.proto;
      out.audio = m;
    }
  }
  return out;
}

std::string rewrite_sdp_connection_and_audio_port(const std::string& sdp, const std::string& new_ip, int new_audio_port) {
  std::istringstream iss(sdp);
  std::ostringstream oss;
  std::string line;
  while (std::getline(iss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (starts_with(line, "c=")) {
      oss << "c=IN IP4 " << new_ip << "\r\n";
      continue;
    }
    if (starts_with(line, "m=audio")) {
      // replace port only
      std::istringstream ls(line);
      std::string m, media;
      int port = 0;
      std::string proto;
      ls >> m >> media >> port >> proto;
      std::string rest;
      std::getline(ls, rest);
      oss << "m=audio " << new_audio_port << " " << proto << rest << "\r\n";
      continue;
    }
    oss << line << "\r\n";
  }
  return oss.str();
}

} // namespace ims::sip

