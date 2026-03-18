#include "ims/auth/auth_provider.hpp"
#include "ims/core/config.hpp"
#include "ims/core/log.hpp"
#include "ims/cx/cx_client.hpp"
#include "ims/dns/dns_resolver.hpp"
#include "ims/media/rtpengine_client.hpp"
#include "ims/media/sdp_rewriter.hpp"
#include "ims/icscf/icscf_service.hpp"
#include "ims/ipsec/xfrm_manager.hpp"
#include "ims/pcscf/pcscf_service.hpp"
#include "ims/policy/qos_hook.hpp"
#include "ims/scscf/scscf_service.hpp"
#include "ims/sip/sip_stack.hpp"
#include "ims/storage/location_service.hpp"
#include "ims/storage/subscription_service.hpp"

#ifdef IMS_HAS_NGHTTP2
#include "ims/n5/n5_client.hpp"
#endif

#include <chrono>
#include <thread>

int main(int argc, char** argv) {
  ims::core::init_logging();
  const char* cfg_path = (argc >= 2) ? argv[1] : "config.yaml";

  ims::core::AppConfig cfg{};
  try {
    cfg = ims::core::load_config(cfg_path);
  } catch (const std::exception& e) {
    ims::core::log()->warn("Load config failed: {} (using defaults)", e.what());
  }

  ims::sip::SipStack sip;

  // Optional: install static xfrm IPsec (requires root / NET_ADMIN)
  if (cfg.ipsec.enabled && cfg.ipsec.mode == "xfrm") {
    ims::ipsec::XfrmConfig xcfg{};
    xcfg.enabled = true;
    xcfg.local_ip = cfg.ipsec.local_ip;
    xcfg.remote_ip = cfg.ipsec.remote_ip;
    xcfg.spi_in = cfg.ipsec.spi_in;
    xcfg.spi_out = cfg.ipsec.spi_out;
    xcfg.enc_algo = cfg.ipsec.enc_algo;
    xcfg.enc_key_hex = cfg.ipsec.enc_key_hex;
    xcfg.auth_algo = cfg.ipsec.auth_algo;
    xcfg.auth_key_hex = cfg.ipsec.auth_key_hex;
    xcfg.reqid = cfg.ipsec.reqid;
    xcfg.proto = cfg.ipsec.proto;
    xcfg.local_port = cfg.ipsec.local_port;
    xcfg.remote_port = cfg.ipsec.remote_port;
    if (!ims::ipsec::XfrmManager::apply(xcfg)) {
      ims::core::log()->error("Failed to apply xfrm IPsec config");
      return 3;
    }
  }

  ims::policy::QosHook qos_hook(ims::policy::QosHookConfig{
      .enabled = cfg.qos.enabled,
      .http_url = cfg.qos.http_url,
      .http_timeout_ms = cfg.qos.http_timeout_ms,
  });

  ims::storage::LocationService location;
  ims::storage::SubscriptionService subscriptions;
  std::unique_ptr<ims::auth::IAuthProvider> auth;
  if (cfg.auth.mode == "md5") {
    auth = std::make_unique<ims::auth::DigestAuthProvider>(cfg.auth.users, cfg.ipsec.enabled);
  } else {
    std::unordered_map<std::string, ims::auth::AkaUserProfile> aka_users;
    for (const auto& [impi, p] : cfg.auth.users_aka) {
      aka_users[impi] = ims::auth::AkaUserProfile{.k_hex = p.k_hex, .opc_hex = p.opc_hex, .sqn_hex = p.sqn_hex, .amf_hex = p.amf_hex};
    }
    auth = std::make_unique<ims::auth::AkaAuthProvider>(std::move(aka_users), cfg.ipsec.enabled);
  }
  ims::media::RtpEngineClient rtpengine(cfg.rtpengine.control_ip, cfg.rtpengine.control_port, cfg.rtpengine.media_public_ip);
  ims::media::SdpRewriter sdp_rewriter;

  // Create Cx client (stub)
  std::unordered_map<std::string, ims::auth::AkaUserProfile> aka_users;
  for (const auto& [impi, p] : cfg.auth.users_aka) {
    aka_users[impi] = ims::auth::AkaUserProfile{.k_hex = p.k_hex, .opc_hex = p.opc_hex, .sqn_hex = p.sqn_hex, .amf_hex = p.amf_hex};
  }
  // Convert Cx capabilities from config
  ims::cx::ServerCapabilities default_caps{};
  for (const auto& cap : cfg.cx.default_capabilities.mandatory_capabilities) {
    default_caps.mandatory_capabilities.push_back(cap);
  }
  for (const auto& cap : cfg.cx.default_capabilities.optional_capabilities) {
    default_caps.optional_capabilities.push_back(cap);
  }
  for (const auto& name : cfg.cx.default_capabilities.mandatory_server_names) {
    default_caps.mandatory_server_names.push_back(name);
  }
  for (const auto& name : cfg.cx.default_capabilities.optional_server_names) {
    default_caps.optional_server_names.push_back(name);
  }
  ims::cx::StubCxClient cx_client(ims::cx::StubCxClient::Config{
      .scscf_uri = cfg.routing.icscf_to_scscf_uri,
      .aka_users = std::move(aka_users),
      .md5_users = cfg.auth.users,
      .default_capabilities = std::move(default_caps),
  });

  // Create S-CSCF with Cx client
  ims::scscf::ScscfService scscf(sip, *auth, cx_client, location, subscriptions, rtpengine, sdp_rewriter, cfg.realm, &qos_hook);

  // Create DNS resolver if enabled
  std::unique_ptr<ims::dns::DnsResolver> dns_resolver;
  if (cfg.dns.enabled) {
    ims::dns::DnsResolver::Config dns_cfg;
    dns_cfg.servers = cfg.dns.servers;
    dns_cfg.timeout_ms = cfg.dns.timeout_ms;
    dns_resolver = std::make_unique<ims::dns::DnsResolver>(dns_cfg);
  }

  ims::icscf::IcscfService icscf(sip, scscf, cx_client, dns_resolver.get(), ims::icscf::IcscfConfig{
      .scscf_sip_uri = cfg.routing.icscf_to_scscf_uri
  });
  ims::pcscf::PcscfService pcscf(sip, icscf);

#ifdef IMS_HAS_NGHTTP2
  // Initialize N5 client if enabled
  if (cfg.n5.enabled) {
    ims::n5::N5ClientConfig n5_cfg;
    n5_cfg.enabled = cfg.n5.enabled;
    n5_cfg.pcf_address = cfg.n5.pcf_address;
    n5_cfg.pcf_port = cfg.n5.pcf_port;
    n5_cfg.timeout_ms = cfg.n5.timeout_ms;
    n5_cfg.use_tls = cfg.n5.use_tls;
    n5_cfg.qos_mapping.voice_5qi = static_cast<ims::n5::FiveQI>(cfg.n5.qos_mapping.voice_5qi);
    n5_cfg.qos_mapping.video_5qi = static_cast<ims::n5::FiveQI>(cfg.n5.qos_mapping.video_5qi);
    n5_cfg.qos_mapping.signaling_5qi = static_cast<ims::n5::FiveQI>(cfg.n5.qos_mapping.signaling_5qi);
    n5_cfg.qos_mapping.default_voice_bitrate_kbps = cfg.n5.qos_mapping.default_voice_bitrate_kbps;
    n5_cfg.qos_mapping.default_video_bitrate_kbps = cfg.n5.qos_mapping.default_video_bitrate_kbps;

    auto n5_client = ims::n5::createN5Client(n5_cfg);
    pcscf.set_n5_client(std::move(n5_client));
    ims::core::log()->info("N5 client initialized (PCF: {}:{})", cfg.n5.pcf_address, cfg.n5.pcf_port);
  }
#endif

  sip.set_on_message([&](const ims::sip::SipMessage& msg) { pcscf.on_sip_message(msg); });
  (void)sip.start_udp(cfg.pcscf.bind_ip, cfg.pcscf.port);

  ims::core::log()->info("imsd started (pcscf {}:{})", cfg.pcscf.bind_ip, cfg.pcscf.port);

  while (true) {
    sip.poll_once(200);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

