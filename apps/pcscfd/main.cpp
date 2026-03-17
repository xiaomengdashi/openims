#include "ims/core/config.hpp"
#include "ims/core/log.hpp"
#include "ims/ipsec/xfrm_manager.hpp"
#include "ims/sip/proxy_router.hpp"
#include "ims/sip/sip_stack.hpp"

#include <chrono>
#include <thread>

int main(int argc, char** argv) {
  ims::core::init_logging();
  const char* cfg_path = (argc >= 2) ? argv[1] : "config.yaml";

  ims::core::AppConfig cfg{};
  try {
    cfg = ims::core::load_config(cfg_path);
  } catch (const std::exception& e) {
    ims::core::log()->error("Load config failed: {}", e.what());
    return 1;
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

  ims::sip::ProxyRouter proxy(
      sip,
      ims::sip::ProxyRouterConfig{
          .realm = cfg.realm,
          .upstream_route_uri = cfg.routing.pcscf_to_icscf_uri,
          .self_uri = cfg.pcscf_proxy.self_uri.empty() ? ("sip:pcscf." + cfg.realm + ":" + std::to_string(cfg.pcscf.port) + ";transport=udp;lr") : cfg.pcscf_proxy.self_uri,
          .via_sent_by = cfg.pcscf_proxy.via_sent_by,
          .topology_hiding = cfg.pcscf_proxy.topology_hiding,
          .pani = cfg.pcscf_proxy.pani.empty() ? std::optional<std::string>{} : std::optional<std::string>{cfg.pcscf_proxy.pani},
          .pvni = cfg.pcscf_proxy.pvni.empty() ? std::optional<std::string>{} : std::optional<std::string>{cfg.pcscf_proxy.pvni},
          .pai = cfg.pcscf_proxy.pai.empty() ? std::optional<std::string>{} : std::optional<std::string>{cfg.pcscf_proxy.pai},
      });

  sip.set_on_message([&](const ims::sip::SipMessage& msg) { proxy.on_message(msg); });
  if (!sip.start_udp(cfg.pcscf.bind_ip, cfg.pcscf.port)) return 2;
  ims::core::log()->info("pcscfd started {}:{}", cfg.pcscf.bind_ip, cfg.pcscf.port);

  while (true) {
    sip.poll_once(200);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

