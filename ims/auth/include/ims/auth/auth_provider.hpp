#pragma once

#include <optional>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace ims::auth {

struct AuthChallenge {
  // 最小化：直接把要放进 WWW-Authenticate 的值交给 SIP 层
  std::string www_authenticate;
  // 用于 verifyResponse 的 opaque nonce/token（MVP 可直接复用 nonce）
  std::string nonce;
};

struct AuthRequest {
  std::string impi;  // IMPI / 私有标识（MVP 可用 from/username 代替）
  std::string realm;
};

struct AuthResponse {
  std::string impi;
  std::string realm;
  std::string method; // e.g. "REGISTER"
  std::string authorization_header;
};

class IAuthProvider {
public:
  virtual ~IAuthProvider() = default;
  virtual std::optional<AuthChallenge> getChallenge(const AuthRequest& req) = 0;
  virtual bool verifyResponse(const AuthResponse& rsp) = 0;
};

// RFC2617 Digest(MD5) 鉴权：从配置加载用户密码，生成 nonce 并校验 Authorization
class DigestAuthProvider final : public IAuthProvider {
public:
  explicit DigestAuthProvider(std::unordered_map<std::string, std::string> user_passwords);

  std::optional<AuthChallenge> getChallenge(const AuthRequest& req) override;
  bool verifyResponse(const AuthResponse& rsp) override;

private:
  std::unordered_map<std::string, std::string> user_passwords_;
};

// 3GPP IMS AKA（AKAv1-MD5）鉴权：
// - 以 Milenage 生成 RAND/AUTN/XRES
// - 将 RAND||AUTN 编码进 nonce（便于 UE 侧解析）
// - 校验 Authorization(Digest ...) 时用 XRES 作为 "password" 复用 RFC2617 计算
struct AkaUserProfile {
  // IMSI/IMPI -> (K, OPc, SQN, AMF)
  // 以 hex 字符串配置（长度：K/OPc=16字节=32 hex；SQN=6字节=12 hex；AMF=2字节=4 hex）
  std::string k_hex;
  std::string opc_hex;
  std::string sqn_hex;
  std::string amf_hex{"8000"};
};

class AkaAuthProvider final : public IAuthProvider {
public:
  explicit AkaAuthProvider(std::unordered_map<std::string, AkaUserProfile> users);

  std::optional<AuthChallenge> getChallenge(const AuthRequest& req) override;
  bool verifyResponse(const AuthResponse& rsp) override;

private:
  struct NonceState {
    std::string impi;
    std::string realm;
    std::string xres_hex; // expected RES in hex
    std::uint64_t created_ms{0};
  };

  std::unordered_map<std::string, AkaUserProfile> users_;
  std::unordered_map<std::string, NonceState> nonce_db_;
};

} // namespace ims::auth

