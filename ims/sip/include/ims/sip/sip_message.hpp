#pragma once

#include <vector>
#include <optional>
#include <string>

namespace ims::sip {

enum class Method { Register, Invite, Ack, Bye, Unknown };

struct SipHeader {
  std::string name;
  std::string value;
};

struct SipStartLine {
  bool is_request{true};
  Method method{Method::Unknown};
  int status_code{0};
  std::string reason;
};

struct SipMessage {
  // eXosip 事务/对话上下文（用于回包）
  int tid{0};
  int did{0};

  SipStartLine start;
  // 对 request：保存 request-uri（用于代理转发/路由）
  std::string request_uri;
  std::string call_id;
  // 便于最小路由：同时保留 username 与原始头部字符串
  std::string from;
  std::string to;
  std::string from_hdr;
  std::string to_hdr;
  std::string contact;
  std::string cseq;
  std::string authorization;
  std::string www_authenticate;
  std::string body;
  std::string content_type;
  // 解析后的全量头域（按收到顺序保存）；用于代理转发/头域操作
  std::vector<SipHeader> headers;
  // 原始 SIP 报文（用于需要完整头域时重建/转发）；可能为空
  std::string raw;

  std::optional<std::string> get_header(const std::string& name) const;
  std::vector<std::string> get_headers(const std::string& name) const;
};

Method parse_method(const std::string& m);

} // namespace ims::sip

