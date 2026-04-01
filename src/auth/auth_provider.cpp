#include "src/auth/auth_provider.hpp"

#include "src/core/log.hpp"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/md5.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <random>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ims::auth {

static std::string random_nonce() {
  static thread_local std::mt19937_64 rng{std::random_device{}()};
  std::uniform_int_distribution<unsigned long long> dist;
  auto v = dist(rng);
  return std::to_string(v);
}

static std::array<unsigned char, 16> random_rand16() {
  static thread_local std::mt19937_64 rng{std::random_device{}()};
  std::uniform_int_distribution<unsigned long long> dist;
  std::array<unsigned char, 16> out{};
  const auto a = dist(rng);
  const auto b = dist(rng);
  std::memcpy(out.data(), &a, 8);
  std::memcpy(out.data() + 8, &b, 8);
  return out;
}

static std::string md5_hex(std::string_view s) {
  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);
  std::ostringstream oss;
  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
  return oss.str();
}

static std::string bytes_hex(const unsigned char* p, std::size_t n) {
  std::ostringstream oss;
  for (std::size_t i = 0; i < n; i++) oss << std::hex << std::setw(2) << std::setfill('0') << (int)p[i];
  return oss.str();
}

static std::optional<std::vector<unsigned char>> hex_to_bytes(std::string_view hex) {
  auto is_hex = [](unsigned char c) { return std::isxdigit(c) != 0; };
  if (hex.size() % 2 != 0) return std::nullopt;
  for (unsigned char c : hex) {
    if (!is_hex(c)) return std::nullopt;
  }
  std::vector<unsigned char> out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); i++) {
    unsigned int v = 0;
    std::string tmp;
    tmp.push_back(static_cast<char>(hex[i * 2]));
    tmp.push_back(static_cast<char>(hex[i * 2 + 1]));
    std::istringstream iss(tmp);
    iss >> std::hex >> v;
    out[i] = static_cast<unsigned char>(v & 0xFF);
  }
  return out;
}

static std::string b64_encode(const unsigned char* p, std::size_t n) {
  // OpenSSL base64: output length is 4*ceil(n/3)
  std::string out;
  out.resize(4 * ((n + 2) / 3));
  const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), p, static_cast<int>(n));
  if (written <= 0) return {};
  out.resize(static_cast<std::size_t>(written));
  return out;
}

static std::optional<std::vector<unsigned char>> b64_decode(std::string_view s) {
  // EVP_DecodeBlock expects padded base64 and may write up to 3/4*n
  std::string in(s);
  // tolerate missing padding
  while (in.size() % 4 != 0) in.push_back('=');
  std::vector<unsigned char> out((in.size() / 4) * 3);
  const int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(in.data()), static_cast<int>(in.size()));
  if (n < 0) return std::nullopt;
  out.resize(static_cast<std::size_t>(n));
  // strip possible zero bytes from '=' padding (EVP_DecodeBlock includes them)
  while (!out.empty() && out.back() == '\0') out.pop_back();
  return out;
}

static std::string trim(std::string s) {
  auto is_ws = [](unsigned char c) { return std::isspace(c) != 0; };
  while (!s.empty() && is_ws((unsigned char)s.front())) s.erase(s.begin());
  while (!s.empty() && is_ws((unsigned char)s.back())) s.pop_back();
  return s;
}

static std::unordered_map<std::string, std::string> parse_digest_kv(std::string_view header) {
  std::unordered_map<std::string, std::string> out;
  auto s = std::string(header);
  auto pos = s.find("Digest");
  if (pos != std::string::npos) s = s.substr(pos + 6);
  s = trim(s);

  std::size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && (s[i] == ',' || std::isspace((unsigned char)s[i]))) i++;
    if (i >= s.size()) break;

    auto eq = s.find('=', i);
    if (eq == std::string::npos) break;
    auto key = trim(s.substr(i, eq - i));
    i = eq + 1;
    if (i >= s.size()) break;

    std::string val;
    if (s[i] == '"') {
      i++;
      auto endq = s.find('"', i);
      if (endq == std::string::npos) break;
      val = s.substr(i, endq - i);
      i = endq + 1;
    } else {
      auto comma = s.find(',', i);
      if (comma == std::string::npos) {
        val = trim(s.substr(i));
        i = s.size();
      } else {
        val = trim(s.substr(i, comma - i));
        i = comma + 1;
      }
    }
    if (!key.empty()) out[key] = val;
  }
  return out;
}

static bool digest_verify_rfc2617(const std::unordered_map<std::string, std::string>& kv, const std::string& method, const std::string& password) {
  const auto username = kv.count("username") ? kv.at("username") : "";
  const auto realm = kv.count("realm") ? kv.at("realm") : "";
  const auto nonce = kv.count("nonce") ? kv.at("nonce") : "";
  const auto uri = kv.count("uri") ? kv.at("uri") : "";
  const auto response = kv.count("response") ? kv.at("response") : "";
  const auto qop = kv.count("qop") ? kv.at("qop") : "";
  const auto nc = kv.count("nc") ? kv.at("nc") : "";
  const auto cnonce = kv.count("cnonce") ? kv.at("cnonce") : "";

  if (username.empty() || realm.empty() || nonce.empty() || uri.empty() || response.empty()) return false;

  const std::string ha1 = md5_hex(username + ":" + realm + ":" + password);
  const std::string ha2 = md5_hex(method + ":" + uri);

  std::string expected;
  if (!qop.empty()) {
    if (cnonce.empty() || nc.empty()) return false;
    expected = md5_hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);
  } else {
    expected = md5_hex(ha1 + ":" + nonce + ":" + ha2);
  }
  return expected == response;
}

DigestAuthProvider::DigestAuthProvider(std::unordered_map<std::string, std::string> user_passwords, bool ipsec_enabled)
    : user_passwords_(std::move(user_passwords)), ipsec_enabled_(ipsec_enabled) {}

std::optional<AuthChallenge> DigestAuthProvider::getChallenge(const AuthRequest& req) {
  AuthChallenge ch{};
  ch.nonce = random_nonce();
  ch.www_authenticate = "Digest realm=\"" + req.realm + "\", nonce=\"" + ch.nonce + "\", algorithm=MD5, qop=\"auth\"";

  if (ipsec_enabled_) {
    ch.www_authenticate += ", integrity-protected=\"yes\"";
    nonce_integrity_required_[ch.nonce] = true;
  }

  return ch;
}

bool DigestAuthProvider::verifyResponse(const AuthResponse& rsp) {
  if (rsp.authorization_header.empty()) return false;
  auto kv = parse_digest_kv(rsp.authorization_header);
  const auto username = kv["username"];
  const auto realm = kv["realm"];
  const auto nonce = kv["nonce"];
  if (username.empty() || realm.empty() || nonce.empty()) return false;
  if (realm != rsp.realm) return false;

  // Check if we sent integrity-protected="yes" for this nonce
  auto integrity_it = nonce_integrity_required_.find(nonce);
  if (integrity_it != nonce_integrity_required_.end()) {
    // If we sent it, UE must echo it back
    const auto integrity_protected = kv.count("integrity-protected") ? kv.at("integrity-protected") : "";
    if (integrity_protected != "yes") {
      ims::core::log()->warn("Digest verify failed: missing or invalid integrity-protected parameter for nonce={}", nonce);
      return false;
    }
    // Remove from tracking since nonce is one-time use
    nonce_integrity_required_.erase(integrity_it);
  }

  auto it = user_passwords_.find(username);
  if (it == user_passwords_.end()) return false;
  const auto& password = it->second;

  const auto method = rsp.method.empty() ? "REGISTER" : rsp.method;
  const bool ok = digest_verify_rfc2617(kv, method, password);
  if (!ok) ims::core::log()->warn("Digest verify failed username={} realm={}", username, realm);
  return ok;
}

// ---- AKA (Milenage) ----

static bool aes_128_encrypt_block(const unsigned char key[16], const unsigned char in[16], unsigned char out[16]) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  int ok = 1;
  int outl = 0;
  ok &= EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
  ok &= EVP_CIPHER_CTX_set_padding(ctx, 0);
  ok &= EVP_EncryptUpdate(ctx, out, &outl, in, 16);
  int finl = 0;
  ok &= EVP_EncryptFinal_ex(ctx, out + outl, &finl);
  EVP_CIPHER_CTX_free(ctx);
  return ok == 1 && (outl + finl) == 16;
}

static void milenage_f1(const unsigned char opc[16],
                        const unsigned char k[16],
                        const unsigned char rand[16],
                        const unsigned char sqn[6],
                        const unsigned char amf[2],
                        unsigned char mac_a[8]) {
  unsigned char tmp1[16], tmp2[16], tmp3[16];
  // TEMP = E_K(RAND XOR OPc)
  for (int i = 0; i < 16; i++) tmp1[i] = rand[i] ^ opc[i];
  (void)aes_128_encrypt_block(k, tmp1, tmp1);

  // IN1 = SQN || AMF || SQN || AMF
  std::memcpy(tmp2, sqn, 6);
  std::memcpy(tmp2 + 6, amf, 2);
  std::memcpy(tmp2 + 8, tmp2, 8);

  // rotate (IN1 XOR OPc) by r1=64 bits (=8 bytes)
  for (int i = 0; i < 16; i++) tmp3[(i + 8) % 16] = tmp2[i] ^ opc[i];
  // XOR with TEMP
  for (int i = 0; i < 16; i++) tmp3[i] ^= tmp1[i];
  // c1 is all zeros => nop
  (void)aes_128_encrypt_block(k, tmp3, tmp1);
  for (int i = 0; i < 16; i++) tmp1[i] ^= opc[i];
  std::memcpy(mac_a, tmp1, 8);
}

static void milenage_f2345(const unsigned char opc[16],
                           const unsigned char k[16],
                           const unsigned char rand[16],
                           unsigned char res[8],
                           unsigned char ak[6]) {
  unsigned char tmp1[16], tmp2[16], tmp3[16];
  // TEMP = E_K(RAND XOR OPc)
  for (int i = 0; i < 16; i++) tmp1[i] = rand[i] ^ opc[i];
  (void)aes_128_encrypt_block(k, tmp1, tmp2);

  // f2 and f5 (r2=0)
  for (int i = 0; i < 16; i++) tmp1[i] = tmp2[i] ^ opc[i];
  tmp1[15] ^= 1; // c2
  (void)aes_128_encrypt_block(k, tmp1, tmp3);
  for (int i = 0; i < 16; i++) tmp3[i] ^= opc[i];
  std::memcpy(ak, tmp3, 6);
  std::memcpy(res, tmp3 + 8, 8);
}

static bool milenage_generate_autn_xres(const unsigned char opc[16],
                                       const unsigned char amf[2],
                                       const unsigned char k[16],
                                       const unsigned char sqn[6],
                                       const unsigned char rand[16],
                                       unsigned char autn[16],
                                       unsigned char xres[8]) {
  unsigned char mac_a[8]{};
  unsigned char ak[6]{};
  milenage_f1(opc, k, rand, sqn, amf, mac_a);
  milenage_f2345(opc, k, rand, xres, ak);
  // AUTN = (SQN ^ AK) || AMF || MAC-A
  for (int i = 0; i < 6; i++) autn[i] = sqn[i] ^ ak[i];
  std::memcpy(autn + 6, amf, 2);
  std::memcpy(autn + 8, mac_a, 8);
  return true;
}

AkaAuthProvider::AkaAuthProvider(std::unordered_map<std::string, AkaUserProfile> users, bool ipsec_enabled)
    : users_(std::move(users)), ipsec_enabled_(ipsec_enabled) {
  // 初始化每个用户的 current_sqn_（从配置的 sqn_hex 解析而来）
  for (const auto& [impi, profile] : users_) {
    auto sqn_bytes = hex_to_bytes(profile.sqn_hex);
    if (sqn_bytes && sqn_bytes->size() == 6) {
      // 将 6 字节 SQN 转换为 uint64_t
      uint64_t sqn = 0;
      for (std::size_t i = 0; i < 6; ++i) {
        sqn = (sqn << 8) | (*sqn_bytes)[i];
      }
      current_sqn_[impi] = sqn;
    }
  }
}

std::optional<AuthChallenge> AkaAuthProvider::getChallenge(const AuthRequest& req) {
  auto it = users_.find(req.impi);
  if (it == users_.end()) {
    ims::core::log()->warn("AKA challenge: unknown impi={}", req.impi);
    return std::nullopt;
  }

  const auto k = hex_to_bytes(it->second.k_hex);
  const auto opc = hex_to_bytes(it->second.opc_hex);
  const auto amf = hex_to_bytes(it->second.amf_hex);
  if (!k || !opc || !amf || k->size() != 16 || opc->size() != 16 || amf->size() != 2) {
    ims::core::log()->warn("AKA profile invalid impi={}", req.impi);
    return std::nullopt;
  }

  // 获取当前用户的 SQN（线程安全）
  uint64_t sqn_val;
  {
    std::lock_guard<std::mutex> lock(sqn_mutex_);
    auto sqn_it = current_sqn_.find(req.impi);
    if (sqn_it == current_sqn_.end()) {
      // 如果没有 current_sqn_，尝试从配置初始化
      auto sqn_bytes = hex_to_bytes(it->second.sqn_hex);
      if (!sqn_bytes || sqn_bytes->size() != 6) {
        ims::core::log()->warn("AKA profile sqn invalid impi={}", req.impi);
        return std::nullopt;
      }
      sqn_val = 0;
      for (std::size_t i = 0; i < 6; ++i) {
        sqn_val = (sqn_val << 8) | (*sqn_bytes)[i];
      }
      current_sqn_[req.impi] = sqn_val;
    } else {
      sqn_val = sqn_it->second;
    }
  }

  // 将 uint64_t SQN 转换为 6 字节数组
  unsigned char sqn_bytes[6]{};
  for (int i = 5; i >= 0; --i) {
    sqn_bytes[i] = static_cast<unsigned char>(sqn_val & 0xFF);
    sqn_val >>= 8;
  }

  auto rand16 = random_rand16();
  unsigned char autn[16]{};
  unsigned char xres[8]{};
  (void)milenage_generate_autn_xres(opc->data(), amf->data(), k->data(), sqn_bytes, rand16.data(), autn, xres);

  // nonce = base64(RAND || AUTN)
  unsigned char nonce_raw[32]{};
  std::memcpy(nonce_raw, rand16.data(), 16);
  std::memcpy(nonce_raw + 16, autn, 16);
  const auto nonce_b64 = b64_encode(nonce_raw, sizeof(nonce_raw));
  if (nonce_b64.empty()) return std::nullopt;

  // store expected xres keyed by nonce
  const auto now_ms = (std::uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count();
  nonce_db_[nonce_b64] = NonceState{.impi = req.impi, .realm = req.realm, .xres_hex = bytes_hex(xres, 8), .created_ms = now_ms};

  AuthChallenge ch{};
  ch.nonce = nonce_b64;
  ch.www_authenticate = "Digest realm=\"" + req.realm +
                        "\", nonce=\"" + nonce_b64 +
                        "\", algorithm=AKAv1-MD5, qop=\"auth\"";

  if (ipsec_enabled_) {
    ch.www_authenticate += ", integrity-protected=\"yes\"";
  }

  return ch;
}

bool AkaAuthProvider::verifyResponse(const AuthResponse& rsp) {
  if (rsp.authorization_header.empty()) return false;
  auto kv = parse_digest_kv(rsp.authorization_header);
  const auto username = kv["username"];
  const auto realm = kv["realm"];
  const auto nonce = kv["nonce"];
  const auto algo = kv.count("algorithm") ? kv.at("algorithm") : "";

  if (username.empty() || realm.empty() || nonce.empty()) return false;
  if (realm != rsp.realm) return false;

  // Validate integrity-protected parameter if IPsec is enabled
  if (ipsec_enabled_) {
    const auto integrity_protected = kv.count("integrity-protected") ? kv.at("integrity-protected") : "";
    if (integrity_protected != "yes") {
      ims::core::log()->warn("AKA verify failed: missing or invalid integrity-protected parameter for nonce={}", nonce);
      return false;
    }
  }
  if (!algo.empty()) {
    const auto a = algo;
    if (a != "AKAv1-MD5" && a != "AKAv2-MD5") {
      ims::core::log()->warn("AKA verify: unsupported algorithm={}", a);
      return false;
    }
  }

  auto it = nonce_db_.find(nonce);
  if (it == nonce_db_.end()) {
    ims::core::log()->warn("AKA verify: nonce not found/expired username={}", username);
    return false;
  }
  const auto& st = it->second;
  if (st.impi != username) {
    ims::core::log()->warn("AKA verify: nonce bound to different impi nonce_impi={} got={}", st.impi, username);
    return false;
  }

  // 检查是否有 AUTS 参数（SQN 不同步的重同步请求）
  if (kv.count("auts")) {
    const auto auts_b64 = kv.at("auts");
    auto auts_bytes = b64_decode(auts_b64);
    if (!auts_bytes || auts_bytes->size() != 14) {
      ims::core::log()->warn("AKA verify: invalid AUTS length username={}", username);
      nonce_db_.erase(it);
      return false;
    }

    // AUTS = MAC-S (8 bytes) + SQN⊕AK (6 bytes)
    unsigned char mac_s[8];
    unsigned char sqn_xor_ak[6];
    std::memcpy(mac_s, auts_bytes->data(), 8);
    std::memcpy(sqn_xor_ak, auts_bytes->data() + 8, 6);

    // 获取用户配置
    auto user_it = users_.find(username);
    if (user_it == users_.end()) {
      nonce_db_.erase(it);
      return false;
    }

    const auto k = hex_to_bytes(user_it->second.k_hex);
    const auto opc = hex_to_bytes(user_it->second.opc_hex);
    const auto amf = hex_to_bytes(user_it->second.amf_hex);
    if (!k || !opc || !amf || k->size() != 16 || opc->size() != 16 || amf->size() != 2) {
      ims::core::log()->warn("AKA profile invalid impi={}", username);
      nonce_db_.erase(it);
      return false;
    }

    // 解析 nonce 为 RAND || AUTN
    auto nonce_decoded = b64_decode(nonce);
    if (!nonce_decoded || nonce_decoded->size() != 32) {
      ims::core::log()->warn("AKA verify: invalid nonce format username={}", username);
      nonce_db_.erase(it);
      return false;
    }

    unsigned char rand[16];
    std::memcpy(rand, nonce_decoded->data(), 16);

    // 生成 AK（用于 SQN 计算）
    unsigned char ak[6];
    unsigned char res_tmp[8];
    milenage_f2345(opc->data(), k->data(), rand, res_tmp, ak);

    // 计算 SQN（SQN = (SQN⊕AK) ⊕ AK）
    unsigned char sqn_resync[6];
    for (int i = 0; i < 6; ++i) {
      sqn_resync[i] = sqn_xor_ak[i] ^ ak[i];
    }

    // 校验 AUTS 中的 MAC-S（需要使用 f1 算法验证）
    unsigned char mac_a[8];
    milenage_f1(opc->data(), k->data(), rand, sqn_resync, amf->data(), mac_a);

    bool mac_valid = true;
    for (int i = 0; i < 8; ++i) {
      if (mac_s[i] != mac_a[i]) {
        mac_valid = false;
        break;
      }
    }

    if (mac_valid) {
      // 重同步成功，更新 stored SQN 为新值
      uint64_t sqn_val = 0;
      for (std::size_t i = 0; i < 6; ++i) {
        sqn_val = (sqn_val << 8) | sqn_resync[i];
      }

      std::lock_guard<std::mutex> lock(sqn_mutex_);
      current_sqn_[username] = sqn_val;
      ims::core::log()->info("AKA resync success username={}, new SQN={}", username, sqn_val);
    } else {
      ims::core::log()->warn("AKA resync failed username={}, MAC verification failed", username);
    }

    // 删除使用过的 nonce（无论成功与否）
    nonce_db_.erase(it);

    // 总是返回 false 以要求 UE 发送新的挑战（使用同步后的 SQN）
    return false;
  }

  // 正常鉴权逻辑（无 AUTS）
  const auto method = rsp.method.empty() ? "REGISTER" : rsp.method;
  const bool ok = digest_verify_rfc2617(kv, method, st.xres_hex);
  if (!ok) {
    ims::core::log()->warn("AKA verify failed username={} realm={}", username, realm);
    nonce_db_.erase(it);
    return false;
  }

  // 鉴权成功，递增 SQN
  {
    std::lock_guard<std::mutex> lock(sqn_mutex_);
    auto sqn_it = current_sqn_.find(username);
    if (sqn_it != current_sqn_.end()) {
      sqn_it->second += 1;
      ims::core::log()->debug("AKA verify success, incremented SQN to {}", sqn_it->second);
    }
  }

  nonce_db_.erase(it);
  return true;
}

} // namespace ims::auth

