#include "gtest/gtest.h"

#include "crypto/common.hh"

TEST(Base64, UnformattedEncode) {
    const crypto::bytestring input(" test string ");
    crypto::bytestring_u output = crypto::base64_encode(input.cmem());

    EXPECT_EQ(crypto::bytestring("IHRlc3Qgc3RyaW5nIA=="), *output);
}

TEST(Base64, UnformattedDecode) {
    const crypto::bytestring input("IHRlc3Qgc3RyaW5nIA==");
    crypto::bytestring_u output = crypto::base64_decode(input.cmem());

    EXPECT_EQ(crypto::bytestring(" test string "), *output);
}

TEST(Base64, UnformattedDecodeReject) {
    const crypto::bytestring input("IHRlc3Qgc\n3RyaW5nIA==");
    crypto::bytestring_u output = crypto::base64_decode(input.cmem());

    EXPECT_EQ(nullptr, output);
}

TEST(Base64, UnformattedEmpty) {
    const crypto::bytestring empty{};

    ASSERT_NE(nullptr, base64_encode(empty.cmem()));
    ASSERT_NE(nullptr, base64_decode(empty.cmem()));
    EXPECT_EQ(empty, *base64_encode(empty.cmem()));
    EXPECT_EQ(empty, *base64_decode(empty.cmem()));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
