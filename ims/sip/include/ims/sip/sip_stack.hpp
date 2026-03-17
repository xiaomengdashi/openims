#pragma once

#include <functional>
#include <string>
#include <unordered_map>

namespace ims::sip {

struct SipMessage;

struct OutOfDialogRequest {
  std::string method;      // "REGISTER"/"INVITE"/...
  std::string to_uri;      // SIP URI
  std::string from_uri;    // SIP URI
  std::string route_uri;   // optional Route (next hop)
  std::string call_id;     // optional override
  std::string body;
  std::string content_type{"application/sdp"};
  std::unordered_map<std::string, std::string> headers; // extra headers
};

struct SipEvent {
  SipMessage* msg{nullptr};
};

class SipStack {
public:
  using OnMessage = std::function<void(const SipMessage&)>;

  SipStack();
  ~SipStack();

  SipStack(const SipStack&) = delete;
  SipStack& operator=(const SipStack&) = delete;

  void set_on_message(OnMessage cb);
  bool start_udp(const std::string& bind_ip, int port);
  void poll_once(int timeout_ms);
  bool send_response_401(const SipMessage& req, const std::string& www_authenticate);
  bool send_response_200_simple(const SipMessage& req, const std::string& contact, const std::string& body = "", const std::string& content_type = "application/sdp");
  bool send_response_302(const SipMessage& req, const std::string& contact);
  bool send_response_with_body(const SipMessage& req, int status_code, const std::string& body, const std::string& content_type = "application/sdp");
  bool send_invite(const std::string& from_uri, const std::string& to_uri, const std::string& request_uri, const std::string& call_id, const std::string& sdp_offer, int& out_did);
  bool send_ack(int tid);
  bool send_bye(int did);
  bool forward_request(const SipMessage& req, const std::string& target_uri);
  bool send_out_of_dialog(const OutOfDialogRequest& req, int& out_tid);

private:
  struct Impl;
  Impl* impl_{nullptr};
};

} // namespace ims::sip

