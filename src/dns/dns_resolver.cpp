#include "src/dns/dns_resolver.hpp"

#include "src/core/log.hpp"

#include <ares.h>
#include <ares_nameser.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <cstring>
#include <algorithm>
#include <memory>
#include <mutex>
#include <condition_variable>

namespace ims::dns {

// Pimpl implementation
class DnsResolver::Impl {
public:
  ares_channel channel_{nullptr};
  Config config_;
  bool initialized_{false};

  explicit Impl(const Config& cfg) : config_(cfg) {
    int status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
      ims::core::log()->error("DNS: c-ares library init failed: {}",
                           ares_strerror(status));
      return;
    }

    ares_options opts{};
    int optmask = 0;

    if (config_.timeout_ms > 0) {
      opts.timeout = config_.timeout_ms / 1000;
      optmask |= ARES_OPT_TIMEOUT;
    }

    status = ares_init_options(&channel_, &opts, optmask);
    if (status != ARES_SUCCESS) {
      ims::core::log()->error("DNS: ares_init_options failed: {}",
                           ares_strerror(status));
      ares_library_cleanup();
      return;
    }

    // If specific servers configured, override system servers
    if (!config_.servers.empty()) {
      // Use CSV format for servers in c-ares 1.19+
      std::string server_csv;
      for (size_t i = 0; i < config_.servers.size(); ++i) {
        if (i > 0) server_csv += ",";
        server_csv += config_.servers[i];
      }

      status = ares_set_servers_csv(channel_, server_csv.c_str());
      if (status != ARES_SUCCESS) {
        ims::core::log()->warn("DNS: Failed to set servers: {}", ares_strerror(status));
      }
    }

    initialized_ = true;
    ims::core::log()->debug("DNS: resolver initialized, {} servers configured",
                         config_.servers.empty() ? "system" : std::to_string(config_.servers.size()));
  }

  ~Impl() {
    if (channel_) {
      ares_destroy(channel_);
    }
    if (initialized_) {
      ares_library_cleanup();
    }
  }

  // Helper: process all events until done
  void processPending() {
    fd_set read_fds, write_fds;
    int nfds;

    while (true) {
      FD_ZERO(&read_fds);
      FD_ZERO(&write_fds);
      nfds = ares_fds(channel_, &read_fds, &write_fds);
      if (nfds == 0) {
        break;
      }

      timeval tv{.tv_sec = config_.timeout_ms / 1000, .tv_usec = (config_.timeout_ms % 1000) * 1000};
      int ret = select(nfds, &read_fds, &write_fds, nullptr, &tv);
      if (ret >= 0) {
        ares_process(channel_, &read_fds, &write_fds);
      }
    }
  }
};

DnsResolver::DnsResolver(const Config& cfg) : impl_(std::make_unique<Impl>(cfg)) {}
DnsResolver::DnsResolver() : impl_(std::make_unique<Impl>(Config())) {}
DnsResolver::~DnsResolver() = default;

bool DnsResolver::isValid() const {
  return impl_->initialized_;
}

// Callback context for generic query
struct QueryCallbackCtx {
  std::vector<uint8_t> data;
  bool done{false};
  int status{ARES_SUCCESS};
  std::mutex mutex;
  std::condition_variable cv;
};

static void genericCallback(void* arg, int status, int timeouts, unsigned char* abuf, int alen) {
  auto* ctx = static_cast<QueryCallbackCtx*>(arg);
  std::lock_guard<std::mutex> lock(ctx->mutex);

  ctx->done = true;
  ctx->status = status;

  if (status == ARES_SUCCESS && abuf && alen > 0) {
    ctx->data.resize(alen);
    std::memcpy(ctx->data.data(), abuf, alen);
  }

  ctx->cv.notify_all();
}

std::vector<DnsNaptrResult> DnsResolver::queryNaptr(const std::string& domain) {
  std::vector<DnsNaptrResult> results;

  if (!impl_->initialized_) {
    ims::core::log()->warn("DNS: resolver not initialized");
    return results;
  }

  QueryCallbackCtx ctx;
  ares_query(impl_->channel_, domain.c_str(), ns_c_in, ns_t_naptr, genericCallback, &ctx);

  // Wait for completion
  {
    std::unique_lock<std::mutex> lock(ctx.mutex);
    while (!ctx.done) {
      ctx.cv.wait_for(lock, std::chrono::milliseconds(impl_->config_.timeout_ms));
      if (!ctx.done) {
        ims::core::log()->warn("DNS: NAPTR query timed out for domain={}", domain);
        return results;
      }
    }
  }

  if (ctx.status != ARES_SUCCESS) {
    ims::core::log()->debug("DNS: NAPTR query failed for domain={}: {}", domain, ares_strerror(ctx.status));
    return results;
  }

  // Parse NAPTR reply
  struct ares_naptr_reply* naptr_reply = nullptr;
  if (ares_parse_naptr_reply(ctx.data.data(), static_cast<int>(ctx.data.size()), &naptr_reply) == ARES_SUCCESS) {
    for (struct ares_naptr_reply* naptr = naptr_reply; naptr; naptr = naptr->next) {
      DnsNaptrResult result;
      result.order = naptr->order;
      result.preference = naptr->preference;
      if (naptr->flags) result.flags = reinterpret_cast<const char*>(naptr->flags);
      if (naptr->service) result.service = reinterpret_cast<const char*>(naptr->service);
      if (naptr->regexp) result.regexp = reinterpret_cast<const char*>(naptr->regexp);
      if (naptr->replacement) result.replacement = naptr->replacement;
      results.push_back(std::move(result));
    }
    ares_free_data(naptr_reply);
  } else {
    ims::core::log()->debug("DNS: Failed to parse NAPTR reply for domain={}", domain);
  }

  return results;
}

std::vector<DnsSrvResult> DnsResolver::querySrv(const std::string& service) {
  std::vector<DnsSrvResult> results;

  if (!impl_->initialized_) {
    ims::core::log()->warn("DNS: resolver not initialized");
    return results;
  }

  QueryCallbackCtx ctx;
  ares_query(impl_->channel_, service.c_str(), ns_c_in, ns_t_srv, genericCallback, &ctx);

  // Wait for completion
  {
    std::unique_lock<std::mutex> lock(ctx.mutex);
    while (!ctx.done) {
      ctx.cv.wait_for(lock, std::chrono::milliseconds(impl_->config_.timeout_ms));
      if (!ctx.done) {
        ims::core::log()->warn("DNS: SRV query timed out for service={}", service);
        return results;
      }
    }
  }

  if (ctx.status != ARES_SUCCESS) {
    ims::core::log()->debug("DNS: SRV query failed for service={}: {}", service, ares_strerror(ctx.status));
    return results;
  }

  // Parse SRV reply
  struct ares_srv_reply* srv_reply = nullptr;
  if (ares_parse_srv_reply(ctx.data.data(), static_cast<int>(ctx.data.size()), &srv_reply) == ARES_SUCCESS) {
    for (struct ares_srv_reply* srv = srv_reply; srv; srv = srv->next) {
      DnsSrvResult result;
      result.priority = srv->priority;
      result.weight = srv->weight;
      result.port = srv->port;
      if (srv->host) result.target = srv->host;
      // Resolve A record for the target
      result.address = queryA(result.target);
      results.push_back(std::move(result));
    }
    ares_free_data(srv_reply);
  } else {
    ims::core::log()->debug("DNS: Failed to parse SRV reply for service={}", service);
  }

  return results;
}

std::string DnsResolver::queryA(const std::string& hostname) {
  // Use standard getaddrinfo for MVP
  struct addrinfo hints{}, *result;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
  if (status != 0) {
    ims::core::log()->debug("DNS: A query failed for {}: {}", hostname, gai_strerror(status));
    return "";
  }

  char ip[INET_ADDRSTRLEN];
  auto* addr_in = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
  inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip));
  freeaddrinfo(result);

  return std::string(ip);
}

std::optional<DnsSrvResult> DnsResolver::resolveScscf(const std::string& domain) {
  // For IMS, the S-CSCF DNS resolution chain is: NAPTR → SRV → A
  // Example NAPTR for S-CSCF: _sip._udp.ims.mnc001.mcc001.3gppnetwork.org

  ims::core::log()->debug("DNS: Resolving S-CSCF for domain={}", domain);

  // First query NAPTR records for SIP services
  std::vector<DnsNaptrResult> naptr_results = queryNaptr(domain);

  // Find NAPTR records with SIP-related services
  std::vector<DnsNaptrResult> sip_naptrs;
  for (const auto& naptr : naptr_results) {
    if (naptr.service.find("SIP") != std::string::npos ||
        naptr.service.find("sip") != std::string::npos ||
        naptr.flags == "S") {
      sip_naptrs.push_back(naptr);
    }
  }

  if (sip_naptrs.empty()) {
    ims::core::log()->debug("DNS: No SIP NAPTR records found for domain={}", domain);
    return std::nullopt;
  }

  // Sort NAPTR records by order then preference
  std::sort(sip_naptrs.begin(), sip_naptrs.end(),
            [](const DnsNaptrResult& a, const DnsNaptrResult& b) {
              if (a.order != b.order) return a.order < b.order;
              return a.preference < b.preference;
            });

  // For each NAPTR record, extract service name and query SRV
  for (const auto& naptr : sip_naptrs) {
    if (!naptr.replacement.empty()) {
      // The replacement field is the SRV domain to query
      std::string srv_domain = naptr.replacement;
      // For example, NAPTR replacement might be "_sip._udp.ims.example.com"
      if (!srv_domain.empty()) {
        std::vector<DnsSrvResult> srv_results = querySrv(srv_domain);
        if (!srv_results.empty()) {
          // Sort SRV records by priority and weight
          std::sort(srv_results.begin(), srv_results.end(),
                    [](const DnsSrvResult& a, const DnsSrvResult& b) {
                      if (a.priority != b.priority) return a.priority < b.priority;
                      return a.weight < b.weight;
                    });
          ims::core::log()->debug("DNS: Found S-CSCF at {}:{}",
                                srv_results[0].target, srv_results[0].port);
          return srv_results[0];
        }
      }
    }
  }

  ims::core::log()->debug("DNS: No S-CSCF SRV records found for domain={}", domain);
  return std::nullopt;
}

std::vector<DnsResult> DnsResolver::resolve_sip_uri(const std::string& uri) {
  // This is a simplified implementation that extracts the domain from the URI
  // and calls resolve()
  std::vector<DnsResult> results;

  // Find the domain part of the URI (simplified)
  size_t host_start = uri.find_first_of("@") + 1;
  if (host_start == std::string::npos || host_start >= uri.size()) {
    ims::core::log()->warn("DNS: Invalid SIP URI format: {}", uri);
    return results;
  }

  size_t host_end = uri.find_first_of(";:", host_start);
  std::string domain = uri.substr(host_start, host_end - host_start);

  return resolve(domain, "sip", "udp");
}

std::vector<DnsResult> DnsResolver::resolve(const std::string& realm,
                                            const std::string& service,
                                            const std::string& protocol) {
  std::vector<DnsResult> results;

  // Build the SRV query name: _<protocol>._<service>.<realm>
  std::string srv_domain = "_" + protocol + "._" + service + "." + realm;
  std::vector<DnsSrvResult> srv_results = querySrv(srv_domain);

  for (const auto& srv : srv_results) {
    DnsResult result;
    result.host = srv.target;
    result.port = srv.port;
    result.transport = protocol;
    results.push_back(std::move(result));
  }

  // If no SRV records found, fall back to A record on default port
  if (results.empty()) {
    std::string a_record = queryA(realm);
    if (!a_record.empty()) {
      DnsResult result;
      result.host = realm;
      result.port = 5060;
      result.transport = protocol;
      results.push_back(std::move(result));
    }
  }

  return results;
}

} // namespace ims::dns
