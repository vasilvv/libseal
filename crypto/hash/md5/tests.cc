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

struct HMACVector {
    const char *key;
    bool hex;
    const char *input;
    const char *output;
};

const std::vector<HMACVector> HMACVectors{
    { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", true,
      "Hi There",
      "9294727a3638bb1c13f48ef8158bfc9d" },
    { "Jefe", false,
      "what do ya want for nothing?",
      "750c783e6ab0b503eaa86e310a5db738" },
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true,
      "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
      "56be34521d144c88dbb8c733f0e8b3f6" },
    { "0102030405060708090a0b0c0d0e0f10111213141516171819", true,
      "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
      "697eaf0aca3a3aea3a75164746ffaa79" },
    { "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", true,
      "Test With Truncation",
      "56461ef2342edc00f9bab995690efd4c" },
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true,
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd" },
    { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true,
      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
      "6f630fad67cda0ee1fb1f562db3aa53e" }
};

const crypto::HashFunctionFactory defaultImpl = []() { return crypto::MD5Base_u(new crypto::MD5Impl()); };

// Test default implementation
TEST(MD5, RFC1321Vectors) {
    size_t num_vectors = sizeof(RFCVectors) / sizeof(RFCVector);
    for (size_t i = 0; i < num_vectors; i++) {
        crypto::bytestring input = crypto::bytestring(
            (const uint8_t *)RFCVectors[i].input, strlen(RFCVectors[i].input));
        crypto::bytestring expected =
            crypto::bytestring::from_hex(RFCVectors[i].output);

        crypto::bytestring_u actual = crypto::hash(defaultImpl, input.mem());
        EXPECT_EQ(expected, *actual);
    }
}

TEST(MD5, RFC2202Vectors) {
    for (auto vector : HMACVectors) {
        crypto::bytestring key;
        if (vector.hex) {
            key = crypto::bytestring::from_hex(vector.key);
        } else {
            key = crypto::bytestring((const uint8_t *)vector.key,
                                     strlen(vector.key));
        }

        crypto::bytestring input = crypto::bytestring(
            (const uint8_t *)vector.input, strlen(vector.input));
        crypto::bytestring expected =
            crypto::bytestring::from_hex(vector.output);

        crypto::bytestring_u actual = crypto::hmac(defaultImpl, key.cmem(), input.cmem());
        EXPECT_EQ(expected, *actual);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
