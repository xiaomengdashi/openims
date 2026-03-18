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

static AppConfig::ProxyConfig parse_proxy(const YAML::Node& n, AppConfig::ProxyConfig def) {
  if (!n) return def;
  if (n["self_uri"]) def.self_uri = n["self_uri"].as<std::string>();
  if (n["via_sent_by"]) def.via_sent_by = n["via_sent_by"].as<std::string>();
  if (n["topology_hiding"]) def.topology_hiding = n["topology_hiding"].as<bool>();
  if (n["pani"]) def.pani = n["pani"].as<std::string>();
  if (n["pvni"]) def.pvni = n["pvni"].as<std::string>();
  if (n["pai"]) def.pai = n["pai"].as<std::string>();
  return def;
}

static AppConfig::IpsecConfig parse_ipsec(const YAML::Node& n, AppConfig::IpsecConfig def) {
  if (!n) return def;
  if (n["enabled"]) def.enabled = n["enabled"].as<bool>();
  if (n["mode"]) def.mode = n["mode"].as<std::string>();
  if (n["local_ip"]) def.local_ip = n["local_ip"].as<std::string>();
  if (n["remote_ip"]) def.remote_ip = n["remote_ip"].as<std::string>();
  if (n["spi_in"]) def.spi_in = n["spi_in"].as<std::string>();
  if (n["spi_out"]) def.spi_out = n["spi_out"].as<std::string>();
  if (n["enc_algo"]) def.enc_algo = n["enc_algo"].as<std::string>();
  if (n["enc_key_hex"]) def.enc_key_hex = n["enc_key_hex"].as<std::string>();
  if (n["auth_algo"]) def.auth_algo = n["auth_algo"].as<std::string>();
  if (n["auth_key_hex"]) def.auth_key_hex = n["auth_key_hex"].as<std::string>();
  if (n["reqid"]) def.reqid = n["reqid"].as<int>();
  if (n["proto"]) def.proto = n["proto"].as<int>();
  if (n["local_port"]) def.local_port = n["local_port"].as<int>();
  if (n["remote_port"]) def.remote_port = n["remote_port"].as<int>();
  return def;
}

static AppConfig::QosHookConfig parse_qos(const YAML::Node& n, AppConfig::QosHookConfig def) {
  if (!n) return def;
  if (n["enabled"]) def.enabled = n["enabled"].as<bool>();
  if (n["http_url"]) def.http_url = n["http_url"].as<std::string>();
  if (n["http_timeout_ms"]) def.http_timeout_ms = n["http_timeout_ms"].as<int>();
  return def;
}

static DhcpConfig parse_dhcp(const YAML::Node& n, DhcpConfig def) {
  if (!n) return def;
  if (n["enabled"]) def.enabled = n["enabled"].as<bool>();
  if (n["bind_ip"]) def.bind_ip = n["bind_ip"].as<std::string>();
  if (n["port"]) def.port = n["port"].as<std::uint16_t>();
  if (n["pcscf_address"]) def.pcscf_address = n["pcscf_address"].as<std::string>();
  if (n["pool_start"]) def.pool_start = n["pool_start"].as<std::string>();
  if (n["pool_end"]) def.pool_end = n["pool_end"].as<std::string>();
  if (n["lease_time_seconds"]) def.lease_time_seconds = n["lease_time_seconds"].as<int>();
  return def;
}

static DnsConfig parse_dns(const YAML::Node& n, DnsConfig def) {
  if (!n) return def;
  if (n["enabled"]) def.enabled = n["enabled"].as<bool>();
  if (n["servers"]) {
    for (const auto& server : n["servers"]) {
      def.servers.push_back(server.as<std::string>());
    }
  }
  if (n["search_domains"]) {
    for (const auto& domain : n["search_domains"]) {
      def.search_domains.push_back(domain.as<std::string>());
    }
  }
  if (n["timeout_ms"]) def.timeout_ms = n["timeout_ms"].as<int>();
  return def;
}

static CxConfig parse_cx(const YAML::Node& n, CxConfig def) {
  if (!n) return def;
  if (n["server_uri"]) def.server_uri = n["server_uri"].as<std::string>();
  if (n["realm"]) def.realm = n["realm"].as<std::string>();
  if (n["host"]) def.host = n["host"].as<std::string>();
  if (n["default_capabilities"]) {
    const auto& caps = n["default_capabilities"];
    if (caps["mandatory_capabilities"]) {
      for (const auto& cap : caps["mandatory_capabilities"]) {
        def.default_capabilities.mandatory_capabilities.push_back(cap.as<int>());
      }
    }
    if (caps["optional_capabilities"]) {
      for (const auto& cap : caps["optional_capabilities"]) {
        def.default_capabilities.optional_capabilities.push_back(cap.as<int>());
      }
    }
    if (caps["mandatory_server_names"]) {
      for (const auto& name : caps["mandatory_server_names"]) {
        def.default_capabilities.mandatory_server_names.push_back(name.as<std::string>());
      }
    }
    if (caps["optional_server_names"]) {
      for (const auto& name : caps["optional_server_names"]) {
        def.default_capabilities.optional_server_names.push_back(name.as<std::string>());
      }
    }
  }
  return def;
}

static N5Config parse_n5(const YAML::Node& n, N5Config def) {
  if (!n) return def;
  if (n["enabled"]) def.enabled = n["enabled"].as<bool>();
  if (n["pcf_address"]) def.pcf_address = n["pcf_address"].as<std::string>();
  if (n["pcf_port"]) def.pcf_port = n["pcf_port"].as<std::uint16_t>();
  if (n["timeout_ms"]) def.timeout_ms = n["timeout_ms"].as<int>();
  if (n["use_tls"]) def.use_tls = n["use_tls"].as<bool>();
  if (n["qos_mapping"]) {
    const auto& qos = n["qos_mapping"];
    if (qos["voice_5qi"]) def.qos_mapping.voice_5qi = qos["voice_5qi"].as<int>();
    if (qos["video_5qi"]) def.qos_mapping.video_5qi = qos["video_5qi"].as<int>();
    if (qos["signaling_5qi"]) def.qos_mapping.signaling_5qi = qos["signaling_5qi"].as<int>();
    if (qos["default_voice_bitrate_kbps"]) def.qos_mapping.default_voice_bitrate_kbps = qos["default_voice_bitrate_kbps"].as<int>();
    if (qos["default_video_bitrate_kbps"]) def.qos_mapping.default_video_bitrate_kbps = qos["default_video_bitrate_kbps"].as<int>();
  }
  return def;
}

static DiameterCxConfig parse_diameter_cx(const YAML::Node& n, DiameterCxConfig def) {
  if (!n) return def;
  if (n["enabled"]) def.enabled = n["enabled"].as<bool>();
  if (n["origin_host"]) def.origin_host = n["origin_host"].as<std::string>();
  if (n["origin_realm"]) def.origin_realm = n["origin_realm"].as<std::string>();
  if (n["destination_host"]) def.destination_host = n["destination_host"].as<std::string>();
  if (n["destination_realm"]) def.destination_realm = n["destination_realm"].as<std::string>();
  if (n["config_file"]) def.config_file = n["config_file"].as<std::string>();
  if (n["timeout_ms"]) def.timeout_ms = n["timeout_ms"].as<int>();
  return def;
}

AppConfig load_config(const std::string& path) {
  AppConfig cfg{};
  YAML::Node root = YAML::LoadFile(path);
  cfg.cx = parse_cx(root["cx"], cfg.cx);
  cfg.dns = parse_dns(root["dns"], cfg.dns);
  cfg.pcscf = parse_sip_endpoint(root["pcscf"], cfg.pcscf);
  cfg.icscf = parse_sip_endpoint(root["icscf"], cfg.icscf);
  cfg.scscf = parse_sip_endpoint(root["scscf"], cfg.scscf);
  cfg.pcscf_proxy = parse_proxy(root["pcscf_proxy"], cfg.pcscf_proxy);
  cfg.icscf_proxy = parse_proxy(root["icscf_proxy"], cfg.icscf_proxy);
  cfg.ipsec = parse_ipsec(root["ipsec"], cfg.ipsec);
  cfg.qos = parse_qos(root["qos"], cfg.qos);
  cfg.dhcp = parse_dhcp(root["dhcp"], cfg.dhcp);
  if (root["routing"]) {
    if (root["routing"]["pcscf_to_icscf_uri"]) cfg.routing.pcscf_to_icscf_uri = root["routing"]["pcscf_to_icscf_uri"].as<std::string>();
    if (root["routing"]["icscf_to_scscf_uri"]) cfg.routing.icscf_to_scscf_uri = root["routing"]["icscf_to_scscf_uri"].as<std::string>();
  }
  cfg.rtpengine = parse_rtpengine(root["rtpengine"], cfg.rtpengine);
  cfg.n5 = parse_n5(root["n5"], cfg.n5);
  cfg.diameter_cx = parse_diameter_cx(root["cx_diameter"], cfg.diameter_cx);
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

