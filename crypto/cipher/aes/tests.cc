#include "gtest/gtest.h"

#include "crypto/cipher/aes.hh"

#include "crypto/testutils/compat_tester.hh"

#include <random>

const crypto::bytestring nist_aes_pt_block =
    crypto::bytestring::from_hex("00112233445566778899aabbccddeeff");
const crypto::bytestring nist_aes128_key_block =
    crypto::bytestring::from_hex("000102030405060708090a0b0c0d0e0f");
const crypto::bytestring nist_aes256_key_block =
    crypto::bytestring::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const crypto::bytestring nist_aes128_ct_block =
    crypto::bytestring::from_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
const crypto::bytestring nist_aes256_ct_block =
    crypto::bytestring::from_hex("8ea2b7ca516745bfeafc49904b496089");

/**
 * Tests an implementation against NIST test vectors for AES-128 and AES-256,
 * both encrpyt and decrypt.
 */
void test_nist_vectors(crypto::AESBase *aes) {
    crypto::bytestring output;
    output.resize(16);

    // Test AES-128
    aes->set_key(nist_aes128_key_block.cmem());
    // Encrypt
    aes->encrypt_block(nist_aes_pt_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes128_ct_block, output);
    // Decrypt
    aes->decrypt_block(nist_aes128_ct_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes_pt_block, output);

    // Test AES-256
    aes->set_key(nist_aes256_key_block.cmem());
    // Encrypt
    aes->encrypt_block(nist_aes_pt_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes256_ct_block, output);
    // Decrypt
    aes->decrypt_block(nist_aes256_ct_block.cptr(), output.ptr());
    EXPECT_EQ(nist_aes_pt_block, output);
}

TEST(ReferenceAES, NISTVectors) {
    crypto::ReferenceAES aes;
    test_nist_vectors(&aes);
}

TEST(ReferenceAES, SelfCompat) {
    crypto::ReferenceAES aesA, aesB;
    crypto::test_randomized_compat(&aesA, &aesB, 10000);
}

TEST(IntelAES, NISTVectors) {
    crypto::IntelAES aes;
    test_nist_vectors(&aes);
}

TEST(IntelAES, SelfCompat) {
    crypto::IntelAES aesA, aesB;
    crypto::test_randomized_compat(&aesA, &aesB, 10000);
}

TEST(IntelAES, ReferenceCompat) {
    crypto::ReferenceAES aesA;
    crypto::IntelAES aesB;
    crypto::test_randomized_compat(&aesA, &aesB, 10000);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
