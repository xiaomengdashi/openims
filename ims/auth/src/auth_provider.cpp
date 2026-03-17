#include "ims/auth/auth_provider.hpp"

#include "ims/core/log.hpp"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/md5.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
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

DigestAuthProvider::DigestAuthProvider(std::unordered_map<std::string, std::string> user_passwords)
    : user_passwords_(std::move(user_passwords)) {}

std::optional<AuthChallenge> DigestAuthProvider::getChallenge(const AuthRequest& req) {
  AuthChallenge ch{};
  ch.nonce = random_nonce();
  ch.www_authenticate = "Digest realm=\"" + req.realm + "\", nonce=\"" + ch.nonce + "\", algorithm=MD5, qop=\"auth\"";
  return ch;
}

bool DigestAuthProvider::verifyResponse(const AuthResponse& rsp) {
  if (rsp.authorization_header.empty()) return false;
  auto kv = parse_digest_kv(rsp.authorization_header);
  const auto username = kv["username"];
  const auto realm = kv["realm"];
  if (username.empty() || realm.empty()) return false;
  if (realm != rsp.realm) return false;

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

AkaAuthProvider::AkaAuthProvider(std::unordered_map<std::string, AkaUserProfile> users) : users_(std::move(users)) {}

std::optional<AuthChallenge> AkaAuthProvider::getChallenge(const AuthRequest& req) {
  auto it = users_.find(req.impi);
  if (it == users_.end()) {
    ims::core::log()->warn("AKA challenge: unknown impi={}", req.impi);
    return std::nullopt;
  }

  const auto k = hex_to_bytes(it->second.k_hex);
  const auto opc = hex_to_bytes(it->second.opc_hex);
  const auto sqn = hex_to_bytes(it->second.sqn_hex);
  const auto amf = hex_to_bytes(it->second.amf_hex);
  if (!k || !opc || !sqn || !amf || k->size() != 16 || opc->size() != 16 || sqn->size() != 6 || amf->size() != 2) {
    ims::core::log()->warn("AKA profile invalid impi={}", req.impi);
    return std::nullopt;
  }

  auto rand16 = random_rand16();
  unsigned char autn[16]{};
  unsigned char xres[8]{};
  (void)milenage_generate_autn_xres(opc->data(), amf->data(), k->data(), sqn->data(), rand16.data(), autn, xres);

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

  // use XRES as "password" for RFC2617 digest
  const auto method = rsp.method.empty() ? "REGISTER" : rsp.method;
  const bool ok = digest_verify_rfc2617(kv, method, st.xres_hex);
  if (!ok) {
    ims::core::log()->warn("AKA verify failed username={} realm={}", username, realm);
    return false;
  }
  // one-time nonce
  nonce_db_.erase(it);
  return true;
}

} // namespace ims::auth

