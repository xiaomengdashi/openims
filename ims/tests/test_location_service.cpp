#include "ims/storage/location_service.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

TEST(LocationService, UpsertLookupExpire) {
  ims::storage::LocationService loc;
  loc.upsert("sip:a@ims.local", "<sip:a@1.2.3.4:5060>", std::chrono::seconds(1));

  auto b1 = loc.lookup("sip:a@ims.local");
  ASSERT_TRUE(b1.has_value());
  EXPECT_EQ(b1->contact, "<sip:a@1.2.3.4:5060>");

  std::this_thread::sleep_for(std::chrono::milliseconds(1100));
  auto b2 = loc.lookup("sip:a@ims.local");
  EXPECT_FALSE(b2.has_value());
}

