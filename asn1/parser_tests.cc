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
bool does_parsing_fail(std::string hex, bool parse_all = true, bool enforce_der = true) {
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
    ASSERT_TRUE(does_parsing_fail("3005050005000500"));
    ASSERT_TRUE(does_parsing_fail("3007050005000500"));

    // Here the length is 4, which results in an unconsumed null at the end
    ASSERT_TRUE (does_parsing_fail("3004040005000500"));
    ASSERT_FALSE(does_parsing_fail("3004040005000500", false));
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
    ASSERT_TRUE(does_parsing_fail("04810100"));
    ASSERT_FALSE(does_parsing_fail("04810100", true, false));

    // Use a redundant byte in the long form
    ASSERT_TRUE(does_parsing_fail("048200ff" + strrep("42", 255)));
    ASSERT_FALSE(does_parsing_fail("048200ff" + strrep("42", 255), true, false));

    // Stress test by using ridiculous length
    ASSERT_TRUE(does_parsing_fail("048f" + strrep("ff", 0xf)));
    ASSERT_TRUE(does_parsing_fail("0484" + strrep("ff", 0xf)));
}

// Composite octet strings (and strings in general) are valid in BER, but not
// in DER
//
//  0   9: OCTET STRING {
//  2   2:   OCTET STRING 00 01
//  6   3:   OCTET STRING 02 03 04
//       :   }
TEST(ParserGeneric, ConstructedString) {
    ASSERT_TRUE(does_parsing_fail("2409040200010403020304"));
    ASSERT_FALSE(does_parsing_fail("2409040200010403020304", true, false));
}

// Deep recursion tests
TEST(ParserGeneric, RecursionLimit) {
    // NULL nested in 100, 1024 and 1025 sequences; limit is 1024
    ASSERT_FALSE(does_parsing_fail(asn1_recursion_test_100));
    ASSERT_FALSE(does_parsing_fail(asn1_recursion_test_1024));
    ASSERT_TRUE (does_parsing_fail(asn1_recursion_test_1025));
}

TEST(ParserGeneric, IndefiniteLength) {
    // Boolean with indefinite length
    ASSERT_TRUE (does_parsing_fail("0180000000", true, false));
    // Terminated and unterminated indef-length sequence
    ASSERT_TRUE (does_parsing_fail("30800101ff", true, false));
    ASSERT_FALSE(does_parsing_fail("30800101ff0000", true, false));

    // Nested indef-length sequences
    //   0 NDEF: SEQUENCE {
    //   2 NDEF:   SEQUENCE {
    //   4    0:     NULL
    //   6    0:     NULL
    //         :     }
    //  10 NDEF:   SEQUENCE {
    //  12    0:     NULL
    //  14    0:     NULL
    //  16    0:     NULL
    //         :     }
    //         :   }
    bytestring nested = bytestring::from_hex("30803080050005000000308005000500050000000000");
    asn1::Parser parser(nested.cmem(), default_options(asn1::BER));
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(asn1::UTSequence));

    asn1::ConstructedData *container = static_cast<asn1::ConstructedData*>(result.get());
    auto &elems = container->get_elements();
    ASSERT_EQ(2, elems.size());
    ASSERT_TRUE(elems[0]->is_universal_type(asn1::UTSequence));
    ASSERT_TRUE(elems[1]->is_universal_type(asn1::UTSequence));

    auto *container0 = static_cast<const asn1::ConstructedData*>(elems[0].get());
    auto *container1 = static_cast<const asn1::ConstructedData*>(elems[1].get());
    ASSERT_EQ(2, container0->get_elements().size());
    ASSERT_EQ(3, container1->get_elements().size());
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
    ASSERT_TRUE(does_parsing_fail("010101"));
    ASSERT_FALSE(does_parsing_fail("010101", true, false));
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
    ASSERT_TRUE(does_parsing_fail("0602ffff"));
}

void string_test_core(const bytestring der, asn1::UniversalType type,
                      std::string &output, bool teletex_as_latin1 = false) {
    asn1::ParserOptions opts;
    opts.treat_teletex_as_latin1 = teletex_as_latin1;
    asn1::Parser parser(der.cmem(), opts);
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(type));

    asn1::TextData *text_data = static_cast<asn1::TextData *>(result.get());
    bytestring_u text = text_data->to_utf8();
    ASSERT_NE(nullptr, text);
    output = text->to_string();
}

TEST(ParserText, NumericString) {
    //   0   5: NumericString '12 34'
    ASSERT_FALSE(does_parsing_fail("12053132203334"));
    //   0   5: NumericString '12 3t'
    ASSERT_TRUE(does_parsing_fail("12053132203374"));
}

TEST(ParserText, PrintableString) {
    //  0   9: PrintableString '*.mit.edu'
    //       :   Error: PrintableString contains illegal character(s).
    // ("*" is not technically allowed, but we allow it because CAs would sign
    //  certs containting this mistake)
    ASSERT_FALSE(does_parsing_fail("13092a2e6d69742e656475"));

    //  0   9: PrintableString '..mit.edu'
    //       :   Error: PrintableString contains illegal character(s).
    ASSERT_TRUE (does_parsing_fail("1309ff2e6d69742e656475"));
}

TEST(ParserText, ASCIIString) {
    bytestring asciistr;
    for (size_t i = 0; i < 128; i++) {
        asciistr.push_back(i);
    }
    bytestring asciistr_der = bytestring::from_hex("168180") + asciistr;

    asn1::Parser parser(asciistr_der.cmem(), default_options());
    asn1::Data_u result = parser.parse_all();

    ASSERT_NE(nullptr, result.get());
    ASSERT_TRUE(result->is_universal_type(asn1::UTASCIIString));
}

TEST(ParserText, BadASCIIString) {
    ASSERT_TRUE(does_parsing_fail("1601f5"));
}

TEST(ParserText, UniversalString) {
    // Test string with four Cyrillic, one ASCII and one SIP CJK characetr
    bytestring str = bytestring::from_hex("1c180000044200000435000004410000044200000020000200a2");
    std::string output;

    string_test_core(str, asn1::UTUniversalString, output);
    EXPECT_EQ("тест 𠂢", output);
}

TEST(ParserText, BMPString) {
    bytestring str = bytestring::from_hex(
        "1e38042104320435044204380442044c00202014002004380020043d0438043a043004"
        "3a04380445002004330432043e04370434043504390021");
    std::string output;

    string_test_core(str, asn1::UTBMPString, output);
    EXPECT_EQ("Светить — и никаких гвоздей!", output);
}

TEST(ParsetText, TeletexString) {
    bytestring str = bytestring::from_hex("1401f2");
    std::string output;

    string_test_core(str, asn1::UTTeletexString, output);
    EXPECT_EQ("đ", output);

    string_test_core(str, asn1::UTTeletexString, output, true);
    EXPECT_EQ("ò", output);
}

// Helper function which takes a string of length between 2^8 and 2^16, turns
// it into a DER UTF8String and then validates it
bool utf8_validation_helper(std::string input) {
    bytestring input_der;
    input_der.push_back(0x0c);  // tag
    input_der.push_back(0x82);  // 2 bytes of length
    input_der.push_back(input.size() >> 8);   // higher bit
    input_der.push_back(input.size() & 0xff);   // lower bit
    input_der.append(reinterpret_cast<const uint8_t*>(input.data()), input.size());

    asn1::Parser parser(input_der.cmem(), default_options());
    asn1::Data_u result = parser.parse_all();

    return result.get() != nullptr;
}

TEST(ParserText, UTF8Validation) {
    // Given that validator internally works in chunks of 1024, we want to test
    // borderline values

    std::string triplet_str = strrep("緑", 1366);    // 4098 bytes
    ASSERT_EQ(4098, triplet_str.size());

    ASSERT_TRUE(utf8_validation_helper(triplet_str));
    EXPECT_FALSE(utf8_validation_helper(triplet_str.substr(0, 4097)));
    EXPECT_FALSE(utf8_validation_helper(triplet_str.substr(0, 4096)));
    EXPECT_TRUE(utf8_validation_helper(triplet_str.substr(0, 4095)));

    EXPECT_FALSE(utf8_validation_helper(triplet_str.substr(0, 1025)));
    EXPECT_FALSE(utf8_validation_helper(triplet_str.substr(0, 1024)));
    EXPECT_TRUE(utf8_validation_helper(triplet_str.substr(0, 1023)));

    // Completely bogus value
    EXPECT_TRUE(does_parsing_fail("0c01ff"));
    // Null
    EXPECT_FALSE(does_parsing_fail("0c0100"));

    // Check if we can disable validation
    bytestring bad_utf8 = bytestring::from_hex("0c01ff");
    asn1::ParserOptions opts = default_options();
    opts.validate_utf8 = false;

    asn1::Parser parser(bad_utf8.cmem(), opts);
    EXPECT_NE(nullptr, parser.parse_all().get());
}

TEST(ParserText, EmptyString) {
    bytestring str = bytestring::from_hex("0c00");
    std::string output;

    string_test_core(str, asn1::UTUTF8String, output);
    EXPECT_EQ("", output);
}

bool time_test_core(std::string input, asn1::UTCTime &output, std::string &parsed, asn1::Encoding enc) {
    bytestring encoded;
    encoded.push_back(0x17);
    encoded.push_back(input.size());
    encoded.append(reinterpret_cast<const uint8_t*>(input.data()), input.size());

    asn1::Parser parser(encoded.cmem(), default_options(enc));
    asn1::Data_u result = parser.parse_all();

    if (!result || !result->is_universal_type(asn1::UTUTCTime)) {
        return false;
    }

    asn1::UTCTimeData *time_data = static_cast<asn1::UTCTimeData *>(result.get());
    output = time_data->parse();
    parsed = time_data->to_string();
    return true;
}

TEST(ParserTime, Time) {
    asn1::UTCTime time;
    std::string parsed;

    // Legitimate date
    ASSERT_TRUE(time_test_core("910102123051Z", time, parsed, asn1::DER));
    EXPECT_EQ("1991-01-02 12:30:51 (UTC)", parsed);
    EXPECT_EQ(1991, time.year);
    EXPECT_EQ(1, time.month);
    EXPECT_EQ(2, time.day);
    EXPECT_EQ(12, time.hour);
    EXPECT_EQ(30, time.minute);
    EXPECT_EQ(51, time.second);
    EXPECT_EQ(0, time.tzoffset);

    // Check wrapping points
    ASSERT_TRUE(time_test_core("500101000000Z", time, parsed, asn1::DER));
    EXPECT_EQ("1950-01-01 00:00:00 (UTC)", parsed);
    ASSERT_TRUE(time_test_core("490101000000Z", time, parsed, asn1::DER));
    EXPECT_EQ("2049-01-01 00:00:00 (UTC)", parsed);

    // Check missing seconds
    ASSERT_FALSE(time_test_core("9101010000Z", time, parsed, asn1::DER));
    ASSERT_TRUE(time_test_core("9101010000Z", time, parsed, asn1::BER));
    EXPECT_EQ("1991-01-01 00:00:00 (UTC)", parsed);

    // Check timezone offset
    ASSERT_FALSE(time_test_core("950208040000+0100", time, parsed, asn1::DER));
    ASSERT_FALSE(time_test_core("950208040000-0100", time, parsed, asn1::DER));
    ASSERT_TRUE(time_test_core("950208040000+0100", time, parsed, asn1::BER));
    EXPECT_EQ("1995-02-08 04:00:00 (UTC+0100)", parsed);
    ASSERT_TRUE(time_test_core("950208040000-0100", time, parsed, asn1::BER));
    EXPECT_EQ("1995-02-08 04:00:00 (UTC-0100)", parsed);

    // Unconsumed data
    ASSERT_FALSE(time_test_core("9101010000Z0000", time, parsed, asn1::BER));
    ASSERT_FALSE(time_test_core("9101010000+00000", time, parsed, asn1::BER));

    /*** Bogus time values ***/
    // Bogus months
    ASSERT_FALSE(time_test_core("950008040000Z", time, parsed, asn1::BER));
    ASSERT_FALSE(time_test_core("951308040000Z", time, parsed, asn1::BER));
    // Bogus days
    ASSERT_FALSE(time_test_core("950200040000Z", time, parsed, asn1::BER));
    ASSERT_FALSE(time_test_core("950431040000Z", time, parsed, asn1::BER));
    ASSERT_FALSE(time_test_core("950229040000Z", time, parsed, asn1::BER));
    // Actual leap year
    ASSERT_TRUE (time_test_core("000229040000Z", time, parsed, asn1::BER));
    // Bogus hour, minute, second
    ASSERT_FALSE(time_test_core("910101240000Z", time, parsed, asn1::BER));
    ASSERT_FALSE(time_test_core("910101236000Z", time, parsed, asn1::BER));
    ASSERT_FALSE(time_test_core("910101230060Z", time, parsed, asn1::BER));
    // Bogus timezone offset
    ASSERT_FALSE(time_test_core("910101230000+2400", time, parsed, asn1::BER));
    ASSERT_FALSE(time_test_core("910101230000+0060", time, parsed, asn1::BER));
    // Borderline valid values
    ASSERT_TRUE (time_test_core("141231235959+2359", time, parsed, asn1::BER));

    // Date with a non-digit character in it
    ASSERT_FALSE(time_test_core("9101021$3051Z", time, parsed, asn1::BER));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
