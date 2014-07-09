#include "gtest/gtest.h"

#include "crypto/cipher/aes.hh"

#include "crypto/testutils/compat_tester.hh"

#include <random>

const crypto::bytestring nist_aes_pt_block{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                            0xcc, 0xdd, 0xee, 0xff };

const crypto::bytestring nist_aes128_key_block{ 0x00, 0x01, 0x02, 0x03,
                                                0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0a, 0x0b,
                                                0x0c, 0x0d, 0x0e, 0x0f };
const crypto::bytestring nist_aes256_key_block{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

const crypto::bytestring nist_aes128_ct_block{ 0x69, 0xc4, 0xe0, 0xd8,
                                               0x6a, 0x7b, 0x04, 0x30,
                                               0xd8, 0xcd, 0xb7, 0x80,
                                               0x70, 0xb4, 0xc5, 0x5a };
const crypto::bytestring nist_aes256_ct_block{ 0x8e, 0xa2, 0xb7, 0xca,
                                               0x51, 0x67, 0x45, 0xbf,
                                               0xea, 0xfc, 0x49, 0x90,
                                               0x4b, 0x49, 0x60, 0x89 };

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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
