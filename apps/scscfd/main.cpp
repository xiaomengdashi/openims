#include "ims/auth/auth_provider.hpp"
#include "ims/core/config.hpp"
#include "ims/core/log.hpp"
#include "ims/media/rtpengine_client.hpp"
#include "ims/media/sdp_rewriter.hpp"
#include "ims/scscf/scscf_service.hpp"
#include "ims/sip/sip_stack.hpp"
#include "ims/storage/location_service.hpp"

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
  ims::storage::LocationService location;
  std::unique_ptr<ims::auth::IAuthProvider> auth;
  if (cfg.auth.mode == "md5") {
    auth = std::make_unique<ims::auth::DigestAuthProvider>(cfg.auth.users);
  } else {
    std::unordered_map<std::string, ims::auth::AkaUserProfile> aka_users;
    for (const auto& [impi, p] : cfg.auth.users_aka) {
      aka_users[impi] = ims::auth::AkaUserProfile{.k_hex = p.k_hex, .opc_hex = p.opc_hex, .sqn_hex = p.sqn_hex, .amf_hex = p.amf_hex};
    }
    auth = std::make_unique<ims::auth::AkaAuthProvider>(std::move(aka_users));
  }

  ims::media::RtpEngineClient rtpengine(cfg.rtpengine.control_ip, cfg.rtpengine.control_port, cfg.rtpengine.media_public_ip);
  ims::media::SdpRewriter sdp_rewriter;
  ims::scscf::ScscfService scscf(sip, *auth, location, rtpengine, sdp_rewriter, cfg.realm);

  sip.set_on_message([&](const ims::sip::SipMessage& msg) { scscf.on_sip_message(msg); });
  if (!sip.start_udp(cfg.scscf.bind_ip, cfg.scscf.port)) return 2;
  ims::core::log()->info("scscfd started {}:{}", cfg.scscf.bind_ip, cfg.scscf.port);

  while (true) {
    sip.poll_once(200);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

