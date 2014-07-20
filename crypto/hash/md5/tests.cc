#include "gtest/gtest.h"

#include "crypto/hash/md5.hh"

struct RFCVector {
    const char *input;
    const char *output;
};

const RFCVector RFCVectors[] = {
    { "", "d41d8cd98f00b204e9800998ecf8427e" },
    { "a", "0cc175b9c0f1b6a831c399e269772661" },
    { "abc", "900150983cd24fb0d6963f7d28e17f72" },
    { "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
    { "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f" },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a" },
};

TEST(MD5, RFC1321Vectors) {
    size_t num_vectors = sizeof(RFCVectors) / sizeof(RFCVector);
    for (size_t i = 0; i < num_vectors; i++) {
        crypto::bytestring input = crypto::bytestring(
            (const uint8_t *)RFCVectors[i].input, strlen(RFCVectors[i].input));
        crypto::bytestring expected =
            crypto::bytestring::from_hex(RFCVectors[i].output);

        crypto::bytestring_u actual = crypto::hash<crypto::MD5>(input.mem());
        EXPECT_EQ(expected, *actual);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
