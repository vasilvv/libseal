#include "crypto/testutils/compat_tester.hh"

#include "gtest/gtest.h"

#include <cstring>
#include <random>

namespace crypto {

void test_randomized_compat(BlockCipher *cipherA, BlockCipher *cipherB, uint32_t iters) {
    std::mt19937 rng;
    rng.seed(12345);    // Use fixed seed so the test is deterministic
    std::uniform_int_distribution<uint8_t> all_bytes;

    bytestring buffer_in, buffer_key, buffer_pt, buffer_ct;
    buffer_in.resize(cipherA->get_block_size());
    buffer_pt.resize(cipherA->get_block_size());
    buffer_ct.resize(cipherA->get_block_size());
    for (uint32_t i = 0; i < iters; i++) {
        for (size_t key_size = 16; key_size <= 32; key_size += 16) {
            // Prepare test key
            buffer_key.resize(key_size);
            for (size_t j = 0; j < buffer_key.size(); j++) {
                buffer_key[j] = all_bytes(rng);
            }
            cipherA->set_key(buffer_key.cmem());
            cipherB->set_key(buffer_key.cmem());

            // Prepare test input
            for (size_t j = 0; j < buffer_in.size(); j++) {
                buffer_in[j] = all_bytes(rng);
            }

            // Check B_dec( A_enc(X) ) == X
            cipherA->encrypt_block(buffer_in.cptr(), buffer_ct.ptr());
            cipherB->decrypt_block(buffer_ct.cptr(), buffer_pt.ptr());
            ASSERT_EQ(buffer_in, buffer_pt);

            // Reset both buffers to avoid success when things don't get touched at
            // all
            memset(buffer_pt.ptr(), 0, buffer_pt.size());
            memset(buffer_ct.ptr(), 0, buffer_ct.size());

            // Check A_dec( B_end(X) ) == X
            cipherB->encrypt_block(buffer_in.cptr(), buffer_ct.ptr());
            cipherA->decrypt_block(buffer_ct.cptr(), buffer_pt.ptr());
            ASSERT_EQ(buffer_in, buffer_pt);
        }
    }
}

}
