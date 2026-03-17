#include "ims/sip/sip_message.hpp"

#include <algorithm>
#include <cctype>

namespace ims::sip {

static std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

Method parse_method(const std::string& m) {
  const auto lm = lower(m);
  if (lm == "register") return Method::Register;
  if (lm == "invite") return Method::Invite;
  if (lm == "ack") return Method::Ack;
  if (lm == "bye") return Method::Bye;
  return Method::Unknown;
}

std::optional<std::string> SipMessage::get_header(const std::string& name) const {
  const auto ln = lower(name);
  if (ln == "call-id") return call_id.empty() ? std::optional<std::string>{} : call_id;
  if (ln == "from") return from.empty() ? std::optional<std::string>{} : from;
  if (ln == "to") return to.empty() ? std::optional<std::string>{} : to;
  if (ln == "contact") return contact.empty() ? std::optional<std::string>{} : contact;
  if (ln == "cseq") return cseq.empty() ? std::optional<std::string>{} : cseq;
  if (ln == "authorization") return authorization.empty() ? std::optional<std::string>{} : authorization;
  if (ln == "www-authenticate") return www_authenticate.empty() ? std::optional<std::string>{} : www_authenticate;
  if (ln == "content-type") return content_type.empty() ? std::optional<std::string>{} : content_type;
  return std::nullopt;
}

} // namespace ims::sip

