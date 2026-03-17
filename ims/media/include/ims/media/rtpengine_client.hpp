#pragma once

#include <optional>
#include <string>

namespace ims::media {

struct RtpOfferResult {
  std::string public_ip;
  int audio_port{0};
};

class RtpEngineClient {
public:
  RtpEngineClient(std::string control_ip, int control_port, std::string public_ip);
  std::optional<RtpOfferResult> offer(const std::string& call_id, const std::string& sdp_offer);
  std::optional<std::string> answer(const std::string& call_id, const std::string& sdp_answer);
  void remove(const std::string& call_id);

private:
  std::string control_ip_;
  int control_port_{0};
  std::string public_ip_;
};

} // namespace ims::media

