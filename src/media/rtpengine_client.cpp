#include "src/media/rtpengine_client.hpp"

#include "src/core/log.hpp"
#include "src/sip/sdp.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace ims::media {

RtpEngineClient::RtpEngineClient(std::string control_ip, int control_port, std::string public_ip)
    : control_ip_(std::move(control_ip)), control_port_(control_port), public_ip_(std::move(public_ip)) {}

namespace {

std::string benc_str(std::string_view s) { return std::to_string(s.size()) + ":" + std::string(s); }
std::string benc_int(long long v) { return "i" + std::to_string(v) + "e"; }

std::string benc_dict(const std::unordered_map<std::string, std::string>& kv) {
  // 简化：不排序 key（rtpengine 通常不要求排序，但严格 bencode 规范要求字典 key 字典序）
  // 这里改为排序，避免兼容性问题。
  std::vector<std::string> keys;
  keys.reserve(kv.size());
  for (const auto& [k, _] : kv) keys.push_back(k);
  std::sort(keys.begin(), keys.end());

  std::string out = "d";
  for (const auto& k : keys) {
    out += benc_str(k);
    out += kv.at(k);
  }
  out += "e";
  return out;
}

struct BencView {
  std::string_view sv;
  std::size_t i{0};

  bool eof() const { return i >= sv.size(); }
  char peek() const { return eof() ? '\0' : sv[i]; }
  char get() { return eof() ? '\0' : sv[i++]; }
};

std::optional<long long> parse_int(BencView& v) {
  if (v.get() != 'i') return std::nullopt;
  std::size_t start = v.i;
  while (!v.eof() && v.peek() != 'e') v.i++;
  if (v.eof()) return std::nullopt;
  auto num = std::string(v.sv.substr(start, v.i - start));
  v.get(); // 'e'
  try {
    return std::stoll(num);
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::string> parse_str(BencView& v) {
  std::size_t start = v.i;
  while (!v.eof() && std::isdigit(static_cast<unsigned char>(v.peek()))) v.i++;
  if (v.eof() || v.peek() != ':') return std::nullopt;
  auto len_s = std::string(v.sv.substr(start, v.i - start));
  v.get(); // ':'
  std::size_t len = 0;
  try {
    len = static_cast<std::size_t>(std::stoul(len_s));
  } catch (...) {
    return std::nullopt;
  }
  if (v.i + len > v.sv.size()) return std::nullopt;
  auto s = std::string(v.sv.substr(v.i, len));
  v.i += len;
  return s;
}

std::optional<std::unordered_map<std::string, std::string>> parse_dict(BencView& v) {
  if (v.get() != 'd') return std::nullopt;
  std::unordered_map<std::string, std::string> out;
  while (!v.eof() && v.peek() != 'e') {
    auto key = parse_str(v);
    if (!key) return std::nullopt;
    // value: only handle str/int or nested dict ignored
    if (v.peek() == 'i') {
      auto iv = parse_int(v);
      if (!iv) return std::nullopt;
      out[*key] = std::to_string(*iv);
    } else if (std::isdigit(static_cast<unsigned char>(v.peek()))) {
      auto sv = parse_str(v);
      if (!sv) return std::nullopt;
      out[*key] = *sv;
    } else if (v.peek() == 'd') {
      // skip nested dict
      auto nested = parse_dict(v);
      if (!nested) return std::nullopt;
    } else {
      return std::nullopt;
    }
  }
  if (v.eof() || v.get() != 'e') return std::nullopt;
  return out;
}

std::optional<std::string> udp_roundtrip(const std::string& ip, int port, const std::string& payload, int timeout_ms) {
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return std::nullopt;

  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return std::nullopt;
  }

  auto sent = ::sendto(fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (sent < 0) {
    ::close(fd);
    return std::nullopt;
  }

  char buf[65535];
  socklen_t alen = sizeof(addr);
  auto n = ::recvfrom(fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&addr), &alen);
  ::close(fd);
  if (n <= 0) return std::nullopt;
  return std::string(buf, buf + n);
}

std::optional<RtpOfferResult> parse_rtpengine_sdp_as_anchor(const std::string& public_ip, const std::string& sdp) {
  auto parsed = ims::sip::parse_sdp_minimal(sdp);
  if (!parsed.audio || parsed.audio->port <= 0) return std::nullopt;
  return RtpOfferResult{.public_ip = public_ip, .audio_port = parsed.audio->port};
}

} // namespace

std::optional<RtpOfferResult> RtpEngineClient::offer(const std::string& call_id, const std::string& sdp_offer) {
  // rtpengine 控制协议：UDP + bencode（最小实现）
  std::unordered_map<std::string, std::string> kv;
  kv["call-id"] = benc_str(call_id);
  kv["command"] = benc_str("offer");
  kv["from-tag"] = benc_str("a");
  kv["sdp"] = benc_str(sdp_offer);
  auto req = benc_dict(kv);

  auto rsp = udp_roundtrip(control_ip_, control_port_, req, 800);
  if (!rsp) {
    ims::core::log()->warn("RTPengine offer timeout/failed ({}:{}) call-id={}", control_ip_, control_port_, call_id);
    return std::nullopt;
  }
  BencView v{.sv = *rsp, .i = 0};
  auto dict = parse_dict(v);
  if (!dict) return std::nullopt;
  auto it = dict->find("result");
  if (it == dict->end() || it->second != "ok") {
    ims::core::log()->warn("RTPengine offer not ok call-id={} result={}", call_id, it == dict->end() ? "missing" : it->second);
    return std::nullopt;
  }
  auto sdp_it = dict->find("sdp");
  if (sdp_it == dict->end()) return std::nullopt;
  return parse_rtpengine_sdp_as_anchor(public_ip_, sdp_it->second);
}

std::optional<std::string> RtpEngineClient::answer(const std::string& call_id, const std::string& sdp_answer) {
  std::unordered_map<std::string, std::string> kv;
  kv["call-id"] = benc_str(call_id);
  kv["command"] = benc_str("answer");
  kv["from-tag"] = benc_str("a");
  kv["to-tag"] = benc_str("b");
  kv["sdp"] = benc_str(sdp_answer);
  auto req = benc_dict(kv);

  auto rsp = udp_roundtrip(control_ip_, control_port_, req, 800);
  if (!rsp) return std::nullopt;
  BencView v{.sv = *rsp, .i = 0};
  auto dict = parse_dict(v);
  if (!dict) return std::nullopt;
  auto it = dict->find("result");
  if (it == dict->end() || it->second != "ok") return std::nullopt;
  auto sdp_it = dict->find("sdp");
  if (sdp_it == dict->end()) return std::nullopt;
  return sdp_it->second;
}

void RtpEngineClient::remove(const std::string& call_id) {
  std::unordered_map<std::string, std::string> kv;
  kv["call-id"] = benc_str(call_id);
  kv["command"] = benc_str("delete");
  kv["from-tag"] = benc_str("a");
  auto req = benc_dict(kv);
  (void)udp_roundtrip(control_ip_, control_port_, req, 300);
}

} // namespace ims::media

