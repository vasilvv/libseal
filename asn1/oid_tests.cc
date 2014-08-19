#include "gtest/gtest.h"

#include "asn1/oid.hh"

asn1::OID OID_from_hex(const char *hexstr) {
    return asn1::OID(crypto::bytestring::from_hex(hexstr));
}

/**
 * This is a binary encoding of
 *     iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1
 * lifted directly from PKCS#1 specification.
 */
const asn1::OID pkcs1OID = OID_from_hex("2A864886F70D0101");

/**
 * This is the test OID,
 *       iso (1) member-body (2) us (840) mit (113554) sipb (4) members(1)
 *           vasilvv(112411) test (1) pastoral-cuttlefish (12345)
 * lifted from a certain other implementation of ASN.1.
 */
const asn1::OID testOID = OID_from_hex("2a864886f712040186ee1b01e039");

TEST(OID, OIDSerialize) {
    EXPECT_EQ(pkcs1OID, asn1::OID({1, 2, 840, 113549, 1, 1}));
    EXPECT_EQ(testOID, asn1::OID({1, 2, 840, 113554, 4, 1, 112411, 1, 12345}));
}

TEST(OID, OIDParse) {
    asn1::OIDComponents_u pkcs1_components = pkcs1OID.get_components();
    ASSERT_NE(nullptr, pkcs1_components);
    EXPECT_EQ(asn1::OIDComponents({1, 2, 840, 113549, 1, 1}), *pkcs1_components);

    asn1::OIDComponents_u test_components = testOID.get_components();
    ASSERT_NE(nullptr, test_components);
    EXPECT_EQ(asn1::OIDComponents({1, 2, 840, 113554, 4, 1, 112411, 1, 12345}), *test_components);
}

TEST(OID, OIDToString) {
    EXPECT_EQ("1.2.840.113549.1.1", pkcs1OID.to_string());
    EXPECT_EQ("1.2.840.113554.4.1.112411.1.12345", testOID.to_string());
    EXPECT_EQ("[invalid OID]", OID_from_hex("ffff").to_string());
}

TEST(OID, OIDParserBad) {
    // Empty OID
    EXPECT_EQ(nullptr, OID_from_hex("").get_components());
    // Truncated OID
    EXPECT_EQ(nullptr, OID_from_hex("ffff").get_components());
    // OID having component exceed 2^64
    EXPECT_EQ(nullptr, OID_from_hex("2affffffffffffffff00").get_components());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

