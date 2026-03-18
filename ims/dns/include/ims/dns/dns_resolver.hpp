#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <cstdint>

namespace ims::dns {

// NAPTR record result
struct DnsNaptrResult {
  std::uint16_t order{0};
  std::uint16_t preference{0};
  std::string flags;
  std::string service;
  std::string regexp;
  std::string replacement;
};

// SRV record result
struct DnsSrvResult {
  std::uint16_t priority{0};
  std::uint16_t weight{0};
  std::uint16_t port{0};
  std::string target;
  std::string address;  // Resolved A record
};

struct DnsResult {
  std::string host;
  std::uint16_t port{5060};
  std::string transport{"udp"};
};

class DnsResolver {
public:
  struct Config {
    std::vector<std::string> servers;  // Override system DNS servers if not empty
    int timeout_ms;

    Config() : servers(), timeout_ms(5000) {}
  };

  explicit DnsResolver(const Config& cfg);
  DnsResolver();
  ~DnsResolver();

  DnsResolver(const DnsResolver&) = delete;
  DnsResolver& operator=(const DnsResolver&) = delete;

  // Check if resolver is properly initialized
  bool isValid() const;

  // Query NAPTR records
  std::vector<DnsNaptrResult> queryNaptr(const std::string& domain);

  // Query SRV records and resolve their A records
  std::vector<DnsSrvResult> querySrv(const std::string& service);

  // Query A record
  std::string queryA(const std::string& hostname);

  // Resolve S-CSCF using NAPTR → SRV → A chain
  std::optional<DnsSrvResult> resolveScscf(const std::string& domain);

  // Resolve SIP URI using NAPTR → SRV → A record chain per 3GPP TS 24.229
  // Returns list of available targets sorted by priority/weight
  std::vector<DnsResult> resolve_sip_uri(const std::string& uri);

  // Resolve using specific domain and service parameters
  std::vector<DnsResult> resolve(const std::string& realm,
                                 const std::string& service = "sip",
                                 const std::string& protocol = "udp");

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace ims::dns
