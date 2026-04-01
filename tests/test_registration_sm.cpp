#include "src/auth/auth_provider.hpp"
#include "src/scscf/registration_sm.hpp"

#include <gtest/gtest.h>
#include <openssl/md5.h>

#include <iomanip>
#include <sstream>
#include <unordered_map>

TEST(RegistrationSM, ChallengeThenOk) {
  ims::auth::DigestAuthProvider auth(std::unordered_map<std::string, std::string>{{"a", "a"}});
  ims::scscf::RegistrationStateMachine sm(auth, "ims.local");
  ims::scscf::RegistrationContext ctx{};

  auto d1 = sm.on_register(ctx, ims::scscf::RegisterRequestView{.aor = "a", .contact = "<sip:a@ims.local>", .authorization = "", .method = "REGISTER"});
  EXPECT_EQ(d1.action, ims::scscf::RegisterDecision::Action::Send401);
  EXPECT_FALSE(d1.www_authenticate.empty());

  // 构造一个能通过 Digest 校验的 Authorization
  // response = MD5( MD5(user:realm:pass) : nonce : nc : cnonce : qop : MD5(method:uri) )
  const std::string realm = "ims.local";
  const std::string nonce = "123";
  const std::string uri = "sip:ims.local";
  const std::string qop = "auth";
  const std::string nc = "00000001";
  const std::string cnonce = "abcdef";

  auto md5hex = [](const std::string& s) -> std::string {
    unsigned char digest[16];
    MD5(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);
    std::ostringstream oss;
    for (int i = 0; i < 16; i++) oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return oss.str();
  };

  const std::string ha1 = md5hex("a:" + realm + ":a");
  const std::string ha2 = md5hex("REGISTER:" + uri);
  const std::string resp = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);

  const std::string authz =
      "Digest username=\"a\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", uri=\"" + uri + "\", "
      "response=\"" + resp + "\", algorithm=MD5, qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce + "\"";

  auto d2 = sm.on_register(ctx, ims::scscf::RegisterRequestView{.aor = "a", .contact = "<sip:a@ims.local>", .authorization = authz, .method = "REGISTER"});
  EXPECT_EQ(d2.action, ims::scscf::RegisterDecision::Action::Send200);
  EXPECT_EQ(ctx.state, ims::scscf::RegistrationState::Registered);
}

