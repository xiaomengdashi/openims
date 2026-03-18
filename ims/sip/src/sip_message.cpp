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
  if (lm == "subscribe") return Method::Subscribe;
  if (lm == "notify") return Method::Notify;
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
  for (const auto& h : headers) {
    if (lower(h.name) == ln) return h.value;
  }
  return std::nullopt;
}

std::vector<std::string> SipMessage::get_headers(const std::string& name) const {
  const auto ln = lower(name);
  std::vector<std::string> out;
  if (ln == "call-id" && !call_id.empty()) out.push_back(call_id);
  if (ln == "from" && !from_hdr.empty()) out.push_back(from_hdr);
  if (ln == "to" && !to_hdr.empty()) out.push_back(to_hdr);
  if (ln == "contact" && !contact.empty()) out.push_back(contact);
  if (ln == "cseq" && !cseq.empty()) out.push_back(cseq);
  if (ln == "authorization" && !authorization.empty()) out.push_back(authorization);
  if (ln == "www-authenticate" && !www_authenticate.empty()) out.push_back(www_authenticate);
  if (ln == "content-type" && !content_type.empty()) out.push_back(content_type);
  for (const auto& h : headers) {
    if (lower(h.name) == ln) out.push_back(h.value);
  }
  return out;
}

} // namespace ims::sip

