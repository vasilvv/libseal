#include "gtest/gtest.h"

#include "asn1/parser.hh"

using crypto::bytestring;
using crypto::bytestring_u;

// Excessively large blobs defined in asn1/parser_test_data.cc
extern const char *asn1_recursion_test_100;
extern const char *asn1_recursion_test_1024;
extern const char *asn1_recursion_test_1025;

asn1::ParserOptions default_options(asn1::Encoding enc = asn1::DER) {
    asn1::ParserOptions options = {};
    options.encoding = enc;
    return options;
}

/**
 * Repeat a string N times.
 */
std::string strrep(std::string str, size_t num_rep) {
    std::string result(str.length() * num_rep, ' ');
    for (size_t i = 0; i < result.length(); i++) {
        result[i] = str[i % str.length()];
    }
    return result;
}

/**
 * Returns if the parsing of given hex-encoded DER blob failed.
 */
bool does_parsing_fails(std::string hex, bool parse_all = true, bool enforce_der = true) {
    bytestring seq = bytestring::from_hex(hex.c_str());

    asn1::Parser parser(seq.cmem(), default_options(enforce_der ? asn1::DER : asn1::BER));
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

TEST(ParserGeneric, LongLengthForm) {
    // Create an octet string which has 256 bytes, repeating "00 01 02 03" as
    // its contents
    bytestring longstr = bytestring::from_hex(("04820100" + strrep("00010203", 64)).c_str());

    asn1::Parser parser(longstr.cmem(), default_options());
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(asn1::UTOctetString));

    const uint8_t *body = result->get_body().cptr();
    for (size_t i = 0; i < result->get_body().size(); i++) {
        ASSERT_EQ(i % 4, body[i]);
    }
}

TEST(ParserGeneric, ShortestLengthConstraint) {
    // Use long form of the length where short would have sufficed
    ASSERT_TRUE(does_parsing_fails("04810100"));
    ASSERT_FALSE(does_parsing_fails("04810100", true, false));

    // Use a redundant byte in the long form
    ASSERT_TRUE(does_parsing_fails("048200ff" + strrep("42", 255)));
    ASSERT_FALSE(does_parsing_fails("048200ff" + strrep("42", 255), true, false));

    // Stress test by using ridiculous length
    ASSERT_TRUE(does_parsing_fails("048f" + strrep("ff", 0xf)));
    ASSERT_TRUE(does_parsing_fails("0484" + strrep("ff", 0xf)));
}

// Composite octet strings (and strings in general) are valid in BER, but not
// in DER
//
//  0   9: OCTET STRING {
//  2   2:   OCTET STRING 00 01
//  6   3:   OCTET STRING 02 03 04
//       :   }
TEST(ParserGeneric, ConstructedString) {
    ASSERT_TRUE(does_parsing_fails("2409040200010403020304"));
    ASSERT_FALSE(does_parsing_fails("2409040200010403020304", true, false));
}

// Deep recursion tests
TEST(ParserGenric, RecursionLimit) {
    // NULL nested in 100, 1024 and 1025 sequences; limit is 1024
    ASSERT_FALSE(does_parsing_fails(asn1_recursion_test_100));
    ASSERT_FALSE(does_parsing_fails(asn1_recursion_test_1024));
    ASSERT_TRUE (does_parsing_fails(asn1_recursion_test_1025));
}

// Basic boolean test, contains only DER-valid bools
//  0   6: SEQUENCE {
//  2   1:   BOOLEAN TRUE
//  5   1:   BOOLEAN FALSE
//       :   }
TEST(ParserBoolean, Basic) {
    bytestring bools = bytestring::from_hex("30060101ff010100");

    asn1::Parser parser(bools.cmem(), default_options());
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(asn1::UTSequence));

    asn1::ConstructedData* container = static_cast<asn1::ConstructedData*>(result.get());
    auto &elems = container->get_elements();
    ASSERT_EQ(2, elems.size());
    for (size_t i = 0; i < 1; i++) {
        ASSERT_TRUE(elems[i]->is_universal_type(asn1::UTBoolean));
        asn1::BooleanData *boolean = static_cast<asn1::BooleanData*>(elems[i].get());
        ASSERT_TRUE(boolean->get() xor i);
    }
}

//  0   1: BOOLEAN TRUE
//       :   Error: BOOLEAN '01' has non-DER encoding.
TEST(ParserBoolean, DERConstraint) {
    ASSERT_TRUE(does_parsing_fails("010101"));
    ASSERT_FALSE(does_parsing_fails("010101", true, false));
}

// Test whether OID parser is integrated correctly and does validate
TEST(ParserOID, GoodOID) {
    auto oid = asn1::OID({1, 2, 840, 113554, 4, 1, 112411, 1, 12345});
    bytestring oidder = bytestring::from_hex("060e2a864886f712040186ee1b01e039");

    asn1::Parser parser(oidder.cmem(), default_options());
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(asn1::UTOID));

    asn1::OIDData *parsed_oid = static_cast<asn1::OIDData*>(result.get());
    EXPECT_EQ(oid, parsed_oid->get());
}

TEST(ParserOID, BadOID) {
    ASSERT_TRUE(does_parsing_fails("0602ffff"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
