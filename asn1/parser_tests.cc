#include "gtest/gtest.h"

#include "asn1/parser.hh"

using crypto::bytestring;
using crypto::bytestring_u;

asn1::ParserOptions default_options(asn1::Encoding enc = asn1::DER) {
    asn1::ParserOptions options = {};
    options.encoding = enc;
    return options;
}

/**
 * Returns if the parsing of given hex-encoded DER blob failed.
 */
bool does_parsing_fails(const char *hex, bool parse_all = true) {
    bytestring seq = bytestring::from_hex(hex);

    asn1::Parser parser(seq.cmem(), default_options());
    asn1::Data_u result = parse_all ? parser.parse_all() : parser.parse();
    return result.get() == nullptr;
}

// A sequence with three nulls in it
//
//  0   6: SEQUENCE {
//  2   0:   NULL
//  4   0:   NULL
//  6   0:   NULL
//       :   }
TEST(ParserGeneric, ThreeNullSequence) {
    bytestring seq = bytestring::from_hex("3006050005000500");

    asn1::Parser parser(seq.cmem(), default_options());
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(asn1::UTSequence));

    asn1::ConstructedData* container = static_cast<asn1::ConstructedData*>(result.get());
    EXPECT_EQ(3, container->get_elements().size());
    for (auto &elem : container->get_elements()) {
        EXPECT_TRUE(elem->is_universal_type(asn1::UTNull));
    }
}

TEST(ParserGeneric, ThreeSequenceNullBadLength) {
    // Same as above, except the length in the first case is 5, and in second
    // is 7
    ASSERT_TRUE(does_parsing_fails("3005050005000500"));
    ASSERT_TRUE(does_parsing_fails("3007050005000500"));

    // Here the length is 4, which results in an unconsumed null at the end
    ASSERT_TRUE (does_parsing_fails("3004040005000500"));
    ASSERT_FALSE(does_parsing_fails("3004040005000500", false));
}

// A set with three context-specific types in it
//
//  0  12: SET {
//  2   2:   [1] AB CD
//  6   3:   [1] AB CD EF
// 11   1:   [1] FF
//       :   }
TEST(ParserGeneric, ThreeBlobSet) {
    bytestring set = bytestring::from_hex("310c8102abcd8103abcdef8101ff");

    asn1::Parser parser(set.cmem(), default_options());
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(asn1::UTSet));

    asn1::ConstructedData* container = static_cast<asn1::ConstructedData*>(result.get());
    EXPECT_EQ(3, container->get_elements().size());
    for (auto &elem : container->get_elements()) {
        EXPECT_EQ(asn1::ContextSpecific, elem->get_class());
    }
}

// A set which is valid in BER but not in DER
//
//  0   9: SET {
//  2   3:   [1] AB CD EF
//  7   2:   [1] AB CD
//       :   }
TEST(ParserGeneric, ThreeBlobSetOrder) {
    bytestring set = bytestring::from_hex("31098103abcdef8102abcd");

    asn1::Parser parser_der(set.cmem(), default_options());
    asn1::Data_u result_der = parser_der.parse_all();

    EXPECT_EQ(nullptr, result_der.get());

    asn1::Parser parser_ber(set.cmem(), default_options(asn1::BER));
    asn1::Data_u result_ber = parser_ber.parse_all();

    ASSERT_NE(nullptr, result_ber.get());
    ASSERT_TRUE(result_ber->is_universal_type(asn1::UTSet));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
