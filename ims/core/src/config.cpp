#include "ims/core/config.hpp"

#include <yaml-cpp/yaml.h>

namespace ims::core {

static SipEndpointConfig parse_sip_endpoint(const YAML::Node& n, SipEndpointConfig def) {
  if (!n) return def;
  if (n["bind_ip"]) def.bind_ip = n["bind_ip"].as<std::string>();
  if (n["port"]) def.port = n["port"].as<std::uint16_t>();
  return def;
}

static RtpEngineConfig parse_rtpengine(const YAML::Node& n, RtpEngineConfig def) {
  if (!n) return def;
  if (n["control_ip"]) def.control_ip = n["control_ip"].as<std::string>();
  if (n["control_port"]) def.control_port = n["control_port"].as<std::uint16_t>();
  if (n["media_public_ip"]) def.media_public_ip = n["media_public_ip"].as<std::string>();
  return def;
}

AppConfig load_config(const std::string& path) {
  AppConfig cfg{};
  YAML::Node root = YAML::LoadFile(path);
  cfg.pcscf = parse_sip_endpoint(root["pcscf"], cfg.pcscf);
  cfg.icscf = parse_sip_endpoint(root["icscf"], cfg.icscf);
  cfg.scscf = parse_sip_endpoint(root["scscf"], cfg.scscf);
  if (root["routing"]) {
    if (root["routing"]["pcscf_to_icscf_uri"]) cfg.routing.pcscf_to_icscf_uri = root["routing"]["pcscf_to_icscf_uri"].as<std::string>();
    if (root["routing"]["icscf_to_scscf_uri"]) cfg.routing.icscf_to_scscf_uri = root["routing"]["icscf_to_scscf_uri"].as<std::string>();
  }
  cfg.rtpengine = parse_rtpengine(root["rtpengine"], cfg.rtpengine);
  if (root["auth"]) {
    if (root["auth"]["mode"]) cfg.auth.mode = root["auth"]["mode"].as<std::string>();
    if (root["auth"]["users"]) {
      for (const auto& it : root["auth"]["users"]) {
        cfg.auth.users[it.first.as<std::string>()] = it.second.as<std::string>();
      }
    }
    if (root["auth"]["users_aka"]) {
      for (const auto& it : root["auth"]["users_aka"]) {
        const auto impi = it.first.as<std::string>();
        const auto n = it.second;
        AuthConfig::AkaProfile p{};
        if (n["k"]) p.k_hex = n["k"].as<std::string>();
        if (n["opc"]) p.opc_hex = n["opc"].as<std::string>();
        if (n["sqn"]) p.sqn_hex = n["sqn"].as<std::string>();
        if (n["amf"]) p.amf_hex = n["amf"].as<std::string>();
        cfg.auth.users_aka[impi] = p;
      }
    }
  }
  if (root["realm"]) cfg.realm = root["realm"].as<std::string>();
  return cfg;
}

} // namespace ims::core

