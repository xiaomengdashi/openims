#pragma once

#include "ims/auth/auth_provider.hpp"

#include <optional>
#include <string>
#include <vector>
#include <unordered_map>

namespace ims::cx {

// Server capabilities for S-CSCF selection (3GPP TS 29.228)
struct ServerCapabilities {
  std::vector<int> mandatory_capabilities;
  std::vector<int> optional_capabilities;
  std::vector<std::string> mandatory_server_names;
  std::vector<std::string> optional_server_names;
};

// User profile response from HSS
struct UserProfile {
  std::string impi;                    // Private Identity (IMPI) - 唯一私有标识
  std::vector<std::string> impus;      // Public Identities (IMPUs) - 一个用户可以有多个公共标识
  std::vector<std::string> psis;       // Public Service Identities (PSIs) - IMS 公共服务标识
  bool registered{false};
  ServerCapabilities scscf_capabilities;
  // AKA profile if available
  std::optional<ims::auth::AkaUserProfile> aka_profile;
  // Digest password if available
  std::optional<std::string> digest_password;

  // Check if this profile includes a specific IMPU/PSI
  bool has_identity(const std::string& identity) const;
};

// Authentication vector request/response
struct AuthenticationVector {
  std::string rand;  // Random challenge (hex)
  std::string autn;  // Authentication token (hex)
  std::string xres;  // Expected response (hex)
  std::string ck;    // Ciphering key (hex)
  std::string ik;    // Integrity key (hex)
};

// Cx interface abstract client (3GPP TS 29.228/29.229)
// MVP: Stub implementation using static config
class ICxClient {
public:
  virtual ~ICxClient() = default;

  // User-Authorization-Request (UAR): Query S-CSCF capabilities for a user
  // Used by I-CSCF during registration to select appropriate S-CSCF
  virtual std::optional<ServerCapabilities> userAuthorization(const std::string& impu, const std::string& visited_network_id) = 0;

  // Location-Information-Request (LIR): Get user registration state and S-CSCF assignment
  // Used by I-CSCF for terminating sessions to find the registered S-CSCF
  virtual std::optional<std::string> getLocation(const std::string& impu) = 0;

  // Multimedia-Authentication-Request (MAR): Get authentication vectors for AKA
  // Used by S-CSCF during registration to challenge the UE
  virtual std::optional<std::vector<AuthenticationVector>> getAuthenticationVector(
      const std::string& impi,
      const std::string& impu,
      const std::string& visited_network_id,
      int num_vectors = 1) = 0;

  // Server-Assignment-Request (SAR): Assign user to S-CSCF
  // Used by S-CSCF to register/deregister a user in HSS
  enum class ServerAssignmentType {
    REGISTRATION,
    RE_REGISTRATION,
    UNREGISTERED_USER,
    TIMEOUT_DEREGISTRATION,
    USER_DEREGISTRATION,
    ADMINISTRATIVE_DEREGISTRATION,
    AUTHENTICATION_FAILURE,
    AUTHENTICATION_TIMEOUT
  };
  virtual bool serverAssignment(const std::string& impi, const std::string& impu, ServerAssignmentType type) = 0;

  // Pull user profile (simplified for MVP)
  virtual std::optional<UserProfile> getUserProfile(const std::string& impu) = 0;
};

// Stub implementation that uses static YAML config (existing auth config)
class StubCxClient final : public ICxClient {
public:
  struct Config {
    // Static S-CSCF URI for terminating calls
    std::string scscf_uri;
    // Static user profiles (from auth config)
    std::unordered_map<std::string, ims::auth::AkaUserProfile> aka_users;
    std::unordered_map<std::string, std::string> md5_users;
    // Default capabilities if not per-user
    ServerCapabilities default_capabilities;
  };

  explicit StubCxClient(Config cfg);

  std::optional<ServerCapabilities> userAuthorization(const std::string& impu, const std::string& visited_network_id) override;
  std::optional<std::string> getLocation(const std::string& impu) override;
  std::optional<std::vector<AuthenticationVector>> getAuthenticationVector(
      const std::string& impi,
      const std::string& impu,
      const std::string& visited_network_id,
      int num_vectors) override;
  bool serverAssignment(const std::string& impi, const std::string& impu, ServerAssignmentType type) override;
  std::optional<UserProfile> getUserProfile(const std::string& impu) override;

private:
  Config cfg_;
  std::unordered_map<std::string, std::string> registered_users_; // impu -> scscf_uri
};

} // namespace ims::cx
