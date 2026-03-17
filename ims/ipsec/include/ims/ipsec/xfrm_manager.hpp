#pragma once

#include <optional>
#include <string>

namespace ims::ipsec {

struct XfrmConfig {
  bool enabled{false};

  // Transport endpoints for ESP (IPv4 for now)
  std::string local_ip;
  std::string remote_ip;

  // Inbound/outbound SPIs (hex, without 0x is ok)
  std::string spi_in;
  std::string spi_out;

  // Encryption/auth algorithms and keys (hex)
  // Examples:
  // - enc_algo: "cbc(aes)"
  // - enc_key_hex: 32/48/64 hex chars for AES-128/192/256
  // - auth_algo: "hmac(sha1)" or "hmac(sha256)"
  // - auth_key_hex: hex
  std::string enc_algo{"cbc(aes)"};
  std::string enc_key_hex;
  std::string auth_algo{"hmac(sha256)"};
  std::string auth_key_hex;

  // Policy selector (ports/proto). For IMS SIP over UDP:
  int proto{17}; // UDP
  int local_port{5060};
  int remote_port{0}; // 0 = any

  // reqid ties policy to state (optional but recommended)
  int reqid{1};
};

class XfrmManager {
public:
  static bool apply(const XfrmConfig& cfg);
  static bool clear(const XfrmConfig& cfg);

private:
  static bool run(const std::string& cmd);
  static std::optional<std::string> normalize_spi(const std::string& s);
  static std::optional<std::string> normalize_hex(const std::string& s);
};

} // namespace ims::ipsec

