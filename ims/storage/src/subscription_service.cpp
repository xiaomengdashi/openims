#include "ims/storage/subscription_service.hpp"

#include <algorithm>
#include <sstream>

namespace ims::storage {

EventPackage parse_event_package(const std::string& event) {
  std::string lower;
  for (unsigned char c : event) {
    lower += static_cast<char>(std::tolower(c));
  }
  if (lower.find("registration") != std::string::npos || lower == "reg") {
    return EventPackage::RegEvent;
  }
  if (lower.find("dialog") != std::string::npos) {
    return EventPackage::DialogEvent;
  }
  if (lower.find("presence") != std::string::npos) {
    return EventPackage::Presence;
  }
  return EventPackage::Unknown;
}

std::string event_package_to_string(EventPackage pkg) {
  switch (pkg) {
    case EventPackage::RegEvent: return "registration-state";
    case EventPackage::DialogEvent: return "dialog";
    case EventPackage::Presence: return "presence";
    case EventPackage::Unknown: return "unknown";
  }
  return "unknown";
}

std::string SubscriptionService::generate_subscription_id(
    const std::string& call_id,
    const std::string& from_tag,
    const std::string& to_tag) {
  std::ostringstream oss;
  oss << call_id;
  if (!from_tag.empty()) {
    oss << "_" << from_tag;
  }
  if (!to_tag.empty()) {
    oss << "_" << to_tag;
  }
  return oss.str();
}

void SubscriptionService::upsert(EventPackage package,
                                  const std::string& notifier_aor,
                                  const std::string& subscriber_aor,
                                  const std::string& subscriber_contact,
                                  const std::string& call_id,
                                  const std::string& from_tag,
                                  const std::string& to_tag,
                                  const std::string& dialog_id,
                                  std::chrono::seconds ttl,
                                  uint32_t initial_cseq) {
  auto sid = generate_subscription_id(call_id, from_tag, to_tag);
  auto now = std::chrono::steady_clock::now();
  subscriptions_[sid] = Subscription{
    .subscription_id = sid,
    .package = package,
    .notifier_aor = notifier_aor,
    .subscriber_aor = subscriber_aor,
    .subscriber_contact = subscriber_contact,
    .call_id = call_id,
    .from_tag = from_tag,
    .to_tag = to_tag,
    .dialog_id = dialog_id,
    .expires_at = now + ttl,
    .last_cseq = initial_cseq,
    .active = true
  };
}

std::optional<Subscription> SubscriptionService::lookup(const std::string& subscription_id) {
  auto it = subscriptions_.find(subscription_id);
  if (it == subscriptions_.end()) {
    return std::nullopt;
  }
  // Check if expired
  auto now = std::chrono::steady_clock::now();
  if (!it->second.active || it->second.expires_at < now) {
    subscriptions_.erase(it);
    return std::nullopt;
  }
  return it->second;
}

std::vector<Subscription> SubscriptionService::find_by_notifier(const std::string& notifier_aor, EventPackage package) {
  std::vector<Subscription> result;
  auto now = std::chrono::steady_clock::now();
  for (const auto& [id, sub] : subscriptions_) {
    if (sub.notifier_aor == notifier_aor && sub.package == package &&
        sub.active && sub.expires_at > now) {
      result.push_back(sub);
    }
  }
  return result;
}

std::vector<Subscription> SubscriptionService::find_by_dialog(const std::string& dialog_id) {
  std::vector<Subscription> result;
  auto now = std::chrono::steady_clock::now();
  for (const auto& [id, sub] : subscriptions_) {
    if (sub.dialog_id == dialog_id && sub.package == EventPackage::DialogEvent &&
        sub.active && sub.expires_at > now) {
      result.push_back(sub);
    }
  }
  return result;
}

void SubscriptionService::remove(const std::string& subscription_id) {
  subscriptions_.erase(subscription_id);
}

void SubscriptionService::purge_expired() {
  auto now = std::chrono::steady_clock::now();
  std::erase_if(subscriptions_, [now](const auto& pair) {
    const auto& sub = pair.second;
    return !sub.active || sub.expires_at < now;
  });
}

size_t SubscriptionService::size() const {
  return subscriptions_.size();
}

} // namespace ims::storage
