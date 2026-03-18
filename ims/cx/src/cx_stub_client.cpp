#include "ims/cx/cx_client.hpp"

#include "ims/core/log.hpp"

#include <random>
#include <algorithm>

namespace ims::cx {

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

std::optional<UserProfile> StubCxClient::getUserProfile(const std::string& impu) {
  ims::core::log()->debug("Cx: Querying user profile for impu={}", impu);

  // MVP: Return static profile based on config
  UserProfile profile;
  profile.impu = impu;
  profile.registered = registered_users_.contains(impu);

  // Find IMPI by IMPU (simplified for MVP)
  for (const auto& [impi, user] : cfg_.aka_users) {
    // Assume impu contains impi
    if (impu.find(impi) != std::string::npos) {
      profile.impi = impi;
      profile.aka_profile = user;
      break;
    }
  }

  // Check if we have digest password
  for (const auto& [username, password] : cfg_.md5_users) {
    if (impu.find(username) != std::string::npos) {
      profile.digest_password = password;
      break;
    }
  }

  profile.scscf_capabilities = cfg_.default_capabilities;

  return profile;
}

} // namespace ims::cx
