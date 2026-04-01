#include "src/cx/cx_client.hpp"

#include "src/core/log.hpp"

#include <random>
#include <algorithm>

namespace ims::cx {

bool UserProfile::has_identity(const std::string& identity) const {
  // Check if identity is in IMPUs
  for (const auto& i : impus) {
    if (i == identity) return true;
  }
  // Check if identity is in PSIs
  for (const auto& p : psis) {
    if (p == identity) return true;
  }
  // Check if identity matches IMPI directly
  if (identity == impi) return true;
  return false;
}

StubCxClient::StubCxClient(Config cfg)
    : cfg_(std::move(cfg)) {}

std::optional<ServerCapabilities> StubCxClient::userAuthorization(const std::string& impu, const std::string& visited_network_id) {
  // MVP: Return default capabilities regardless of user
  ims::core::log()->debug("Cx: User-Authorization-Request for impu={}", impu);
  return cfg_.default_capabilities;
}

std::optional<std::string> StubCxClient::getLocation(const std::string& impu) {
  ims::core::log()->debug("Cx: Location-Information-Request for impu={}", impu);

  // Check if user is registered
  auto it = registered_users_.find(impu);
  if (it != registered_users_.end()) {
    ims::core::log()->debug("Cx: User {} registered at S-CSCF: {}", impu, it->second);
    return it->second;
  }

  // If not registered, return static S-CSCF URI from config
  if (!cfg_.scscf_uri.empty()) {
    ims::core::log()->debug("Cx: User {} not registered, returning default S-CSCF: {}", impu, cfg_.scscf_uri);
    return cfg_.scscf_uri;
  }

  ims::core::log()->debug("Cx: No S-CSCF assignment for impu={}", impu);
  return std::nullopt;
}

std::optional<std::vector<AuthenticationVector>> StubCxClient::getAuthenticationVector(
    const std::string& impi,
    const std::string& impu,
    const std::string& visited_network_id,
    int num_vectors) {
  ims::core::log()->debug("Cx: Multimedia-Authentication-Request for impi={}, impu={}", impi, impu);

  // MVP: Generate random vectors for testing
  std::vector<AuthenticationVector> vectors;

  // Check if we have AKA profile for this user
  auto user_it = cfg_.aka_users.find(impi);
  if (user_it != cfg_.aka_users.end()) {
    // Generate random authentication vectors
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    auto random_hex = [&](int length) -> std::string {
      std::string hex;
      for (int i = 0; i < length; ++i) {
        const char* digits = "0123456789abcdef";
        hex += digits[dis(gen)];
      }
      return hex;
    };

    for (int i = 0; i < num_vectors; ++i) {
      AuthenticationVector av;
      av.rand = random_hex(32);  // 16 bytes
      av.autn = random_hex(32);  // 16 bytes
      av.xres = random_hex(16);  // 8 bytes
      av.ck = random_hex(32);    // 16 bytes
      av.ik = random_hex(32);    // 16 bytes
      vectors.push_back(std::move(av));
    }
  }

  return vectors;
}

bool StubCxClient::serverAssignment(const std::string& impi, const std::string& impu, ServerAssignmentType type) {
  ims::core::log()->debug("Cx: Server-Assignment-Request for impi={}, impu={}, type={}", impi, impu, static_cast<int>(type));

  if (type == ServerAssignmentType::REGISTRATION || type == ServerAssignmentType::RE_REGISTRATION) {
    registered_users_[impu] = cfg_.scscf_uri;
    ims::core::log()->info("Cx: User {} registered to S-CSCF: {}", impu, cfg_.scscf_uri);
    return true;
  } else if (type == ServerAssignmentType::USER_DEREGISTRATION ||
             type == ServerAssignmentType::TIMEOUT_DEREGISTRATION ||
             type == ServerAssignmentType::ADMINISTRATIVE_DEREGISTRATION) {
    registered_users_.erase(impu);
    ims::core::log()->info("Cx: User {} deregistered", impu);
    return true;
  }

  return false;
}

std::optional<UserProfile> StubCxClient::getUserProfile(const std::string& identity) {
  ims::core::log()->debug("Cx: Querying user profile for identity={}", identity);

  // MVP: Return static profile based on config
  UserProfile profile;
  profile.registered = registered_users_.contains(identity);

  // Find IMPI by identity - first check AKA users
  for (const auto& [impi, user] : cfg_.aka_users) {
    if (impi == identity || identity.find(impi) != std::string::npos) {
      profile.impi = impi;
      profile.impus.push_back(identity);
      profile.aka_profile = user;
      break;
    }
  }

  // If not found in AKA, check MD5 users
  if (profile.impi.empty()) {
    for (const auto& [username, password] : cfg_.md5_users) {
      if (username == identity || identity.find(username) != std::string::npos) {
        profile.impi = username;
        profile.impus.push_back(identity);
        profile.digest_password = password;
        break;
      }
    }
  }

  // If still not found, check if this is a registered user by any other name
  if (profile.impi.empty() && !profile.registered) {
    ims::core::log()->warn("Cx: No profile found for identity={}", identity);
    return std::nullopt;
  }

  profile.scscf_capabilities = cfg_.default_capabilities;

  return profile;
}

} // namespace ims::cx
