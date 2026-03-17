#include "ims/core/config.hpp"
#include "ims/core/log.hpp"
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
  ims::sip::ProxyRouter proxy(
      sip,
      ims::sip::ProxyRouterConfig{
          .realm = cfg.realm,
          .upstream_route_uri = cfg.routing.pcscf_to_icscf_uri,
          .self_uri = "sip:pcscf." + cfg.realm + ":" + std::to_string(cfg.pcscf.port) + ";transport=udp;lr",
      });

  sip.set_on_message([&](const ims::sip::SipMessage& msg) { proxy.on_message(msg); });
  if (!sip.start_udp(cfg.pcscf.bind_ip, cfg.pcscf.port)) return 2;
  ims::core::log()->info("pcscfd started {}:{}", cfg.pcscf.bind_ip, cfg.pcscf.port);

  while (true) {
    sip.poll_once(200);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

