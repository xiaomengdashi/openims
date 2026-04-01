#include "src/storage/location_service.hpp"

namespace ims::storage {

void LocationService::upsert(const std::string& aor, const std::string& contact, std::chrono::seconds ttl) {
  RegistrationBinding b{};
  b.aor = aor;
  b.contact = contact;
  b.expires_at = std::chrono::steady_clock::now() + ttl;
  map_[aor] = b;
}

std::optional<RegistrationBinding> LocationService::lookup(const std::string& aor) {
  purge_expired();
  auto it = map_.find(aor);
  if (it == map_.end()) return std::nullopt;
  return it->second;
}

void LocationService::remove(const std::string& aor) { map_.erase(aor); }

void LocationService::purge_expired() {
  const auto now = std::chrono::steady_clock::now();
  for (auto it = map_.begin(); it != map_.end();) {
    if (it->second.expires_at <= now) it = map_.erase(it);
    else ++it;
  }
}

} // namespace ims::storage

