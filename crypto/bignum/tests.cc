#include "gtest/gtest.h"

#include "crypto/bignum.hh"
#include "crypto/testutils/test_data.hh"

#include <fstream>

TEST(Bignum, Zero) {
    crypto::Bignum<2048> test;
    ASSERT_EQ(true, !test);
}

TEST(Bignum, Hex) {
    crypto::Bignum<128> test(1);
    ASSERT_EQ("00000000000000000000000000000001", test.to_hex());

    crypto::Bignum<128> inverse_test;
    ASSERT_TRUE(inverse_test.from_hex("ffffffffffffffffffffffffffffffff"));
    inverse_test.bin_inverse();
    ASSERT_FALSE(inverse_test);
}

TEST(Bignum, Bitflip) {
    crypto::Bignum<128> test(1);
    test.bin_inverse();
    ASSERT_EQ("fffffffffffffffffffffffffffffffe", test.to_hex());
}

// FIXME: this needs more tests
TEST(Bignum, Add) {
    crypto::Bignum<128> test_a(1);
    test_a.bin_inverse();
    crypto::Bignum<128> test_b(1);
    bool carryout;

    crypto::BNAdd<128>(test_a, test_b, test_a, 0, carryout);
    EXPECT_EQ("ffffffffffffffffffffffffffffffff", test_a.to_hex());
    EXPECT_FALSE(carryout);

    crypto::BNAdd<128>(test_a, test_b, test_a, 0, carryout);
    EXPECT_EQ("00000000000000000000000000000000", test_a.to_hex());
    EXPECT_TRUE(carryout);

    crypto::BNAdd(test_a, test_b, test_a, 1, carryout);
    EXPECT_EQ("00000000000000000000000000000002", test_a.to_hex());
    EXPECT_FALSE(carryout);

    crypto::BNSub(test_a, test_b, test_a);
    EXPECT_EQ("00000000000000000000000000000001", test_a.to_hex());

    crypto::Bignum<256> test_c;
    test_c.bin_inverse();
    crypto::Bignum<256> test_d = test_c;
    crypto::BNAdd<256>(test_c, test_d, test_c, 0, carryout);
    EXPECT_EQ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe", test_c.to_hex());
    EXPECT_TRUE(carryout);

    test_a = crypto::Bignum<128>();
    test_a.data64()[0] = UINT64_MAX;
    test_b = crypto::Bignum<128>(1);
    crypto::BNAdd<128>(test_a, test_b, test_a, 0, carryout);
    EXPECT_EQ("00000000000000010000000000000000", test_a.to_hex());
    EXPECT_FALSE(carryout);
}

TEST(BignumArith, Add) {
    std::ifstream test_data_file(crypto::test_data_path("test-data-add.txt"), std::ifstream::in);
    ASSERT_TRUE(test_data_file);

    while (test_data_file) {
        std::string header;
        std::getline(test_data_file, header);
        if (header == "EOF") {
            break;
        }
        ASSERT_EQ("------", header);

        std::string a_hex;
        std::string b_hex;
        std::string result_hex;
        std::getline(test_data_file, a_hex);
        std::getline(test_data_file, b_hex);
        std::getline(test_data_file, result_hex);

        crypto::Bignum<256> a;
        crypto::Bignum<256> b;
        crypto::Bignum<256> actual;
        crypto::Bignum<256> expected;
        bool carryout;

        ASSERT_TRUE(a.from_hex(a_hex));
        ASSERT_TRUE(b.from_hex(b_hex));
        ASSERT_TRUE(expected.from_hex(result_hex));

        BNAdd(a, b, actual, 0, carryout);
        ASSERT_EQ(result_hex, actual.to_hex());
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
