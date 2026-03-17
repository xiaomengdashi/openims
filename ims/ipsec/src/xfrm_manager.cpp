#include "ims/ipsec/xfrm_manager.hpp"

#include "ims/core/log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace ims::ipsec {

static std::string trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
  return s;
}

std::optional<std::string> XfrmManager::normalize_hex(const std::string& s) {
  auto t = trim(s);
  if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
  if (t.empty()) return std::nullopt;
  for (char c : t) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) return std::nullopt;
  }
  std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return t;
}

std::optional<std::string> XfrmManager::normalize_spi(const std::string& s) {
  auto h = normalize_hex(s);
  if (!h) return std::nullopt;
  // ip xfrm expects spi as hex with 0x prefix
  return "0x" + *h;
}

bool XfrmManager::run(const std::string& cmd) {
  ims::core::log()->info("xfrm: {}", cmd);
  const int rc = std::system(cmd.c_str());
  return rc == 0;
}

bool XfrmManager::apply(const XfrmConfig& cfg) {
  if (!cfg.enabled) return true;
  if (cfg.local_ip.empty() || cfg.remote_ip.empty()) {
    ims::core::log()->error("xfrm: local_ip/remote_ip required");
    return false;
  }
  auto spi_in = normalize_spi(cfg.spi_in);
  auto spi_out = normalize_spi(cfg.spi_out);
  auto enc_key = normalize_hex(cfg.enc_key_hex);
  auto auth_key = normalize_hex(cfg.auth_key_hex);
  if (!spi_in || !spi_out || !enc_key || !auth_key) {
    ims::core::log()->error("xfrm: invalid spi/key hex");
    return false;
  }

  // Best-effort: clear first to avoid duplicates.
  (void)clear(cfg);

  // Add ESP states (in/out)
  // Outbound: src=local dst=remote
  if (!run("ip xfrm state add src " + cfg.local_ip + " dst " + cfg.remote_ip +
           " proto esp spi " + *spi_out +
           " reqid " + std::to_string(cfg.reqid) +
           " mode transport" +
           " enc '" + cfg.enc_algo + "' 0x" + *enc_key +
           " auth '" + cfg.auth_algo + "' 0x" + *auth_key)) {
    return false;
  }

  // Inbound: src=remote dst=local
  if (!run("ip xfrm state add src " + cfg.remote_ip + " dst " + cfg.local_ip +
           " proto esp spi " + *spi_in +
           " reqid " + std::to_string(cfg.reqid) +
           " mode transport" +
           " enc '" + cfg.enc_algo + "' 0x" + *enc_key +
           " auth '" + cfg.auth_algo + "' 0x" + *auth_key)) {
    return false;
  }

  // Add policies (out/in). Selector keeps it scoped to SIP/UDP unless remote_port=0.
  const std::string sel_out = " proto " + std::to_string(cfg.proto) +
                              " sport " + std::to_string(cfg.local_port) +
                              (cfg.remote_port > 0 ? (" dport " + std::to_string(cfg.remote_port)) : "");
  const std::string sel_in = " proto " + std::to_string(cfg.proto) +
                             (cfg.remote_port > 0 ? (" sport " + std::to_string(cfg.remote_port)) : "") +
                             " dport " + std::to_string(cfg.local_port);

  if (!run("ip xfrm policy add dir out src " + cfg.local_ip + " dst " + cfg.remote_ip +
           " sel" + sel_out +
           " tmpl src " + cfg.local_ip + " dst " + cfg.remote_ip + " proto esp reqid " + std::to_string(cfg.reqid) + " mode transport")) {
    return false;
  }

  if (!run("ip xfrm policy add dir in src " + cfg.remote_ip + " dst " + cfg.local_ip +
           " sel" + sel_in +
           " tmpl src " + cfg.remote_ip + " dst " + cfg.local_ip + " proto esp reqid " + std::to_string(cfg.reqid) + " mode transport")) {
    return false;
  }

  return true;
}

bool XfrmManager::clear(const XfrmConfig& cfg) {
  if (!cfg.enabled) return true;
  auto spi_in = normalize_spi(cfg.spi_in);
  auto spi_out = normalize_spi(cfg.spi_out);
  if (!spi_in || !spi_out) return true;

  // Best-effort deletions (ignore failure)
  (void)run("ip xfrm policy delete dir out src " + cfg.local_ip + " dst " + cfg.remote_ip + " 2>/dev/null");
  (void)run("ip xfrm policy delete dir in src " + cfg.remote_ip + " dst " + cfg.local_ip + " 2>/dev/null");
  (void)run("ip xfrm state delete src " + cfg.local_ip + " dst " + cfg.remote_ip + " proto esp spi " + *spi_out + " 2>/dev/null");
  (void)run("ip xfrm state delete src " + cfg.remote_ip + " dst " + cfg.local_ip + " proto esp spi " + *spi_in + " 2>/dev/null");
  return true;
}

} // namespace ims::ipsec

