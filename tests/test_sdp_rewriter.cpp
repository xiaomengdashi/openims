#include "src/media/sdp_rewriter.hpp"

#include <gtest/gtest.h>

TEST(SdpRewriter, RewritesConnectionAndAudioPort) {
  const std::string sdp =
      "v=0\r\n"
      "o=- 0 0 IN IP4 10.0.0.2\r\n"
      "s=-\r\n"
      "c=IN IP4 10.0.0.2\r\n"
      "t=0 0\r\n"
      "m=audio 49170 RTP/AVP 0 8 96\r\n";

  ims::media::SdpRewriter r;
  const auto out = r.rewrite_offer(sdp, "1.2.3.4", 40000);
  EXPECT_NE(out.find("c=IN IP4 1.2.3.4"), std::string::npos);
  EXPECT_NE(out.find("m=audio 40000"), std::string::npos);
}

