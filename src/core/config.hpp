#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

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

struct DhcpConfig {
  bool enabled{false};
  std::string bind_ip{"0.0.0.0"};
  std::uint16_t port{67};  // Standard DHCPv4 server port
  std::string pcscf_address;  // P-CSCF IPv4 for Option 15
  std::string pool_start;     // IP address pool start
  std::string pool_end;       // IP address pool end
  int lease_time_seconds{3600};
};

struct DnsConfig {
  bool enabled{false};
  // DNS server addresses (optional, system DNS used if empty)
  std::vector<std::string> servers;
  // Search domains (optional)
  std::vector<std::string> search_domains;
  // Timeout in milliseconds (default 5000ms)
  int timeout_ms{5000};
};

struct CxConfig {
  // HSS server URI (for Diameter)
  std::string server_uri{""};
  // HSS realm (for Diameter)
  std::string realm{"ims.hss.local"};
  // Default HSS host (for Diameter)
  std::string host{"hss.ims.local"};

  // Default S-CSCF capabilities for Cx (UAR) response (3GPP TS 24.229)
  struct ServerCapabilities {
    std::vector<int> mandatory_capabilities;
    std::vector<int> optional_capabilities;
    std::vector<std::string> mandatory_server_names;
    std::vector<std::string> optional_server_names;
  };
  ServerCapabilities default_capabilities;
};

// N5 interface configuration (P-CSCF <-> PCF)
// 3GPP TS 29.514 Npcf_PolicyAuthorization
struct N5Config {
  bool enabled{false};
  std::string pcf_address{"127.0.0.1"};
  std::uint16_t pcf_port{8080};
  int timeout_ms{5000};
  bool use_tls{false};

  // QoS mapping configuration
  struct QosMappingConfig {
    int voice_5qi{1};
    int video_5qi{2};
    int signaling_5qi{5};
    int default_voice_bitrate_kbps{64};
    int default_video_bitrate_kbps{384};
  } qos_mapping;
};

// Diameter Cx client configuration (S-CSCF <-> UDM/HSS)
// Uses freeDiameter library
struct DiameterCxConfig {
  bool enabled{false};
  std::string origin_host{"scscf.ims.local"};
  std::string origin_realm{"ims.local"};
  std::string destination_host{"hss.ims.local"};
  std::string destination_realm{"ims.local"};
  std::string config_file{"/etc/freeDiameter/freeDiameter.conf"};
  int timeout_ms{5000};
};

struct AppConfig {
  SipEndpointConfig pcscf;
  SipEndpointConfig icscf;
  SipEndpointConfig scscf;
  DnsConfig dns;
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
  CxConfig cx;
  DhcpConfig dhcp;
  N5Config n5;
  DiameterCxConfig diameter_cx;
  std::string realm{"ims.local"};
};

AppConfig load_config(const std::string& path);

} // namespace ims::core

