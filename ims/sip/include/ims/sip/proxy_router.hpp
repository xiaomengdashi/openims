#pragma once

#include "ims/sip/sip_message.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

namespace ims::sip {

class SipStack;

struct ProxyRouterConfig {
  std::string realm{"ims.local"};

  // Where to send inbound UE requests (P-CSCF -> I-CSCF)
  std::string upstream_route_uri{}; // e.g. "sip:127.0.0.1:5061;transport=udp"

  // Publicly-reachable URI representing this proxy (used in Record-Route/Path)
  // e.g. "sip:pcscf.ims.local:5060;transport=udp;lr"
  std::string self_uri{};

  // If true, attempt to strip/normalize topology-revealing headers on forward/relay.
  bool topology_hiding{false};

  // Optional static headers to add if missing (P-CSCF basics)
  std::optional<std::string> pani;
  std::optional<std::string> pvni;
  std::optional<std::string> pai; // e.g. "<sip:+8613800138000@ims.mnc001.mcc460.3gppnetwork.org>"
};

// Minimal stateful SIP proxy router:
// - forwards requests upstream
// - correlates downstream responses to upstream transactions (tid)
// - performs basic P-CSCF header-chain handling (Via/Record-Route/Path/PANI/PVNI/PAI)
class ProxyRouter {
public:
  using NextHopSelector = std::function<std::string(const SipMessage&)>;

  ProxyRouter(SipStack& sip, ProxyRouterConfig cfg);

  void on_message(const SipMessage& msg);

private:
  struct Leg {
    int upstream_tid{0};
    Method upstream_method{Method::Unknown};
  };

  void on_request(const SipMessage& req);
  void on_response(const SipMessage& resp);

  bool should_record_route(const SipMessage& req) const;
  bool should_add_path(const SipMessage& req) const;

  SipStack& sip_;
  ProxyRouterConfig cfg_;
  std::unordered_map<int, Leg> downstream_tid_to_leg_;
};

} // namespace ims::sip

