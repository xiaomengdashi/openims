#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace ims::core {

struct SipEndpointConfig {
  std::string bind_ip{"0.0.0.0"};
  std::uint16_t port{5060};
};

struct RtpEngineConfig {
  std::string control_ip{"127.0.0.1"};
  std::uint16_t control_port{2223};
  std::string media_public_ip{"127.0.0.1"};
};

struct AuthConfig {
  // 支持两种模式：
  // - md5: RFC2617 Digest(MD5)，users 为 username->password
  // - aka: 3GPP IMS AKA (AKAv1-MD5)，users_aka 为 impi->AKA profile
  std::string mode{"aka"};
  std::unordered_map<std::string, std::string> users; // md5: username -> password
  struct AkaProfile {
    std::string k_hex;
    std::string opc_hex;
    std::string sqn_hex;
    std::string amf_hex{"8000"};
  };
  std::unordered_map<std::string, AkaProfile> users_aka;
};

struct AppConfig {
  SipEndpointConfig pcscf;
  SipEndpointConfig icscf;
  SipEndpointConfig scscf;
  struct RoutingConfig {
    std::string pcscf_to_icscf_uri{"sip:127.0.0.1:5061;transport=udp"};
    std::string icscf_to_scscf_uri{"sip:127.0.0.1:5062;transport=udp"};
  } routing;
  RtpEngineConfig rtpengine;
  AuthConfig auth;
  std::string realm{"ims.local"};
};

AppConfig load_config(const std::string& path);

} // namespace ims::core

