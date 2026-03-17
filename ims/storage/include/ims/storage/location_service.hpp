#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>

namespace ims::storage {

struct RegistrationBinding {
  std::string aor;
  std::string contact;
  std::chrono::steady_clock::time_point expires_at;
};

class LocationService {
public:
  void upsert(const std::string& aor, const std::string& contact, std::chrono::seconds ttl);
  std::optional<RegistrationBinding> lookup(const std::string& aor);
  void remove(const std::string& aor);
  void purge_expired();

private:
  std::unordered_map<std::string, RegistrationBinding> map_;
};

} // namespace ims::storage

