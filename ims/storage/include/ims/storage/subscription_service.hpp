#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>

namespace ims::storage {

enum class EventPackage {
  RegEvent,        // registration-state (RFC 3680)
  DialogEvent,     // dialog (RFC 4235)
  Presence,        // presence (RFC 3856) - optional
  Unknown
};

// Convert event package string from SIP header to enum
EventPackage parse_event_package(const std::string& event);
std::string event_package_to_string(EventPackage pkg);

struct Subscription {
  std::string subscription_id;
  EventPackage package;
  std::string notifier_aor;       // The entity being subscribed to (e.g., the registered user)
  std::string subscriber_aor;     // The subscriber that will receive notifications
  std::string subscriber_contact; // Contact URI where to send NOTIFY
  std::string call_id;            // Call-ID from SUBSCRIBE request
  std::string from_tag;           // From tag for dialog identification
  std::string to_tag;             // To tag for dialog identification
  std::string dialog_id;          // Associated dialog (for dialog-event)
  std::chrono::steady_clock::time_point expires_at;
  uint32_t last_cseq;             // Last CSeq used for NOTIFY
  bool active{true};
};

class SubscriptionService {
public:
  // Create or update a subscription
  void upsert(EventPackage package,
              const std::string& notifier_aor,
              const std::string& subscriber_aor,
              const std::string& subscriber_contact,
              const std::string& call_id,
              const std::string& from_tag,
              const std::string& to_tag,
              const std::string& dialog_id,
              std::chrono::seconds ttl,
              uint32_t initial_cseq);

  // Lookup a subscription by ID
  std::optional<Subscription> lookup(const std::string& subscription_id);

  // Lookup subscriptions by notifier (what is being subscribed to)
  std::vector<Subscription> find_by_notifier(const std::string& notifier_aor, EventPackage package);

  // Lookup subscriptions by dialog (for dialog-event)
  std::vector<Subscription> find_by_dialog(const std::string& dialog_id);

  // Remove a subscription
  void remove(const std::string& subscription_id);

  // Remove all expired subscriptions
  void purge_expired();

  // Get total count of active subscriptions
  size_t size() const;

  // Generate a unique subscription ID from call-id and tags
  static std::string generate_subscription_id(const std::string& call_id,
                                               const std::string& from_tag,
                                               const std::string& to_tag);

private:
  std::unordered_map<std::string, Subscription> subscriptions_;
};

} // namespace ims::storage
