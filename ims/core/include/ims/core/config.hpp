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
  struct ProxyConfig {
    // Publicly reachable SIP URI for this proxy hop (used in Record-Route/Path/topology hiding)
    // e.g. "sip:pcscf.ims.local:5060;transport=udp;lr"
    std::string self_uri{};
    // Optional explicit Via sent-by (host[:port]) for forwarded requests
    std::string via_sent_by{};
    bool topology_hiding{false};
    // Optional headers to inject if missing (P-CSCF basics)
    std::string pani{};
    std::string pvni{};
    std::string pai{};
  };
  ProxyConfig pcscf_proxy;
  ProxyConfig icscf_proxy;

  struct IpsecConfig {
    bool enabled{false};
    // "xfrm" (static keys) for now
    std::string mode{"xfrm"};
    // xfrm config (UE<->P-CSCF)
    std::string local_ip{};
    std::string remote_ip{};
    std::string spi_in{};
    std::string spi_out{};
    std::string enc_algo{"cbc(aes)"};
    std::string enc_key_hex{};
    std::string auth_algo{"hmac(sha256)"};
    std::string auth_key_hex{};
    int reqid{1};
    int proto{17};
    int local_port{5060};
    int remote_port{0};
  } ipsec;

  struct QosHookConfig {
    bool enabled{false};
    // If set, will POST JSON events using curl(1).
    std::string http_url{};
    int http_timeout_ms{1500};
  } qos;
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

