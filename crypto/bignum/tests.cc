#include "gtest/gtest.h"

#include "crypto/bignum.hh"
#include "crypto/testutils/test_data.hh"

#include <fstream>

crypto::Bignum_u bn_from_hex(std::string s) {
    crypto::Bignum_u result(new crypto::Bignum(s.size() / 2));
    result->from_hex(s);
    return result;
}

namespace crypto {

::std::ostream& operator<<(::std::ostream& os, const Bignum& bar) {
    os << bar.to_hex();
    return os;
}

}

TEST(Bignum, Zero) {
    crypto::Bignum test(2048 / 8);
    ASSERT_EQ(true, !test);
}

TEST(Bignum, Hex) {
    crypto::Bignum test(128 / 8, 1);
    ASSERT_EQ("00000000000000000000000000000001", test.to_hex());

    crypto::Bignum inverse_test(128 / 8, 0);
    ASSERT_TRUE(inverse_test.from_hex("ffffffffffffffffffffffffffffffff"));
    inverse_test.bin_inverse();
    ASSERT_FALSE(inverse_test);
}

TEST(Bignum, Bitflip) {
    crypto::Bignum test(128 / 8, 1);
    test.bin_inverse();
    ASSERT_EQ("fffffffffffffffffffffffffffffffe", test.to_hex());
}

TEST(Bignum, Shift) {
    crypto::Bignum test(1024 / 8, 2);
    crypto::Bignum two(1024 / 8, 2);

    size_t runs;
    for (runs = 0; test; runs++) {
        crypto::Bignum previous = test;

        crypto::Bignum_u expected = test.multiply_by(two)->half();
        test.shift_left_by_one();
        ASSERT_EQ(*expected, test);

        if (!*expected) {
            break;
        }

        test.shift_right_by_one();
        ASSERT_EQ(previous, test);

        test.shift_left_by_one();
    }

    ASSERT_EQ(1022, runs);
}

// FIXME: this needs more tests
TEST(Bignum, Add) {
    crypto::Bignum test_a(128 / 8, 1);
    crypto::Bignum test_b(128 / 8, 1);
    test_a.bin_inverse();

    bool carryout;

    test_a.increase_by(test_b, 0, carryout);
    EXPECT_EQ("ffffffffffffffffffffffffffffffff", test_a.to_hex());
    EXPECT_FALSE(carryout);

    test_a.increase_by(test_b, 0, carryout);
    EXPECT_EQ("00000000000000000000000000000000", test_a.to_hex());
    EXPECT_TRUE(carryout);

    test_a.increase_by(test_b, 1, carryout);
    EXPECT_EQ("00000000000000000000000000000002", test_a.to_hex());
    EXPECT_FALSE(carryout);

    test_a.decrease_by(test_b);
    EXPECT_EQ("00000000000000000000000000000001", test_a.to_hex());

    crypto::Bignum test_c(256 / 8, 0);
    test_c.bin_inverse();
    crypto::Bignum test_d = test_c;

    crypto::Bignum_u test_e = test_c.add_to(test_d, 0, carryout);
    EXPECT_EQ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe", test_e->to_hex());
    EXPECT_TRUE(carryout);
}

TEST(Bignum, Mul) {
    crypto::Bignum test_a(128 / 8, 2);
    crypto::Bignum test_b(128 / 8, 3);
    crypto::Bignum_u result;

    result = test_a.multiply_by(test_b);
    EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000006", result->to_hex());

    test_a.zero();
    test_b.zero();
    test_a.bin_inverse();
    test_b.bin_inverse();
    result = test_a.multiply_by(test_b);
    EXPECT_EQ("fffffffffffffffffffffffffffffffe00000000000000000000000000000001", result->to_hex());

    crypto::Bignum test_c(256 / 8);
    crypto::Bignum test_d(256 / 8);

    test_c.bin_inverse();
    test_d.bin_inverse();
    result = test_c.multiply_by(test_d);
    EXPECT_EQ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000000000000000000000000000000000000000000001", result->to_hex());
}

TEST(BignumData, Add) {
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
        std::string result_plus_one_hex;
        std::getline(test_data_file, a_hex);
        std::getline(test_data_file, b_hex);
        std::getline(test_data_file, result_hex);
        std::getline(test_data_file, result_plus_one_hex);

        crypto::Bignum_u a = bn_from_hex(a_hex);
        crypto::Bignum_u b = bn_from_hex(b_hex);
        crypto::Bignum_u actual;

        ASSERT_FALSE(!a);
        ASSERT_FALSE(!b);

        // Without carry-in
        actual = a->add_to(*b);
        ASSERT_EQ(result_hex, actual->to_hex());

        // With carry-in
        bool discard;
        actual = a->add_to(*b, 1, discard);
        ASSERT_EQ(result_plus_one_hex, actual->to_hex());
    }
}

TEST(BignumData, Mul) {
    std::ifstream test_data_file(crypto::test_data_path("test-data-mul.txt"), std::ifstream::in);
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

        crypto::Bignum_u a = bn_from_hex(a_hex);
        crypto::Bignum_u b = bn_from_hex(b_hex);
        crypto::Bignum_u actual;

        ASSERT_FALSE(!a);
        ASSERT_FALSE(!b);

        actual = a->multiply_by(*b);
        ASSERT_EQ(a->bytelen * 2, actual->bytelen);
        ASSERT_EQ(result_hex, actual->to_hex());
    }
}

TEST(BignumData, DivMod) {
    std::ifstream test_data_file(crypto::test_data_path("test-data-divmod.txt"), std::ifstream::in);
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
        std::string quotient_hex;
        std::string remainder_hex;
        std::getline(test_data_file, a_hex);
        std::getline(test_data_file, b_hex);
        std::getline(test_data_file, quotient_hex);
        std::getline(test_data_file, remainder_hex);

        crypto::Bignum_u a = bn_from_hex(a_hex);
        crypto::Bignum_u b = bn_from_hex(b_hex);

        ASSERT_FALSE(!a);
        ASSERT_FALSE(!b);

        crypto::DivModResults_u actual = a->divide(*b);
        ASSERT_EQ(quotient_hex, actual->quotient.to_hex());
        ASSERT_EQ(remainder_hex, actual->remainder.to_hex());
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
