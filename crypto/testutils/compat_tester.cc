#include "crypto/testutils/compat_tester.hh"

#include "gtest/gtest.h"

#include <cstring>
#include <random>

namespace crypto {

void test_randomized_compat(BlockCipherFactory implA,
                            BlockCipherFactory implB, size_t key_size,
                            uint32_t iters) {
    std::mt19937 rng;
    rng.seed(12345); // Use fixed seed so the test is deterministic
    std::uniform_int_distribution<uint8_t> all_bytes;

    size_t block_size;
    bytestring bogus_key(key_size);
    block_size = implA(bogus_key.cmem())->get_block_size();
    ASSERT_EQ(block_size, implB(bogus_key.cmem())->get_block_size());

    bytestring buffer_in, buffer_key, buffer_pt, buffer_ct;
    buffer_in.resize(block_size);
    buffer_pt.resize(block_size);
    buffer_ct.resize(block_size);
    for (uint32_t i = 0; i < iters; i++) {
        // Prepare test key
        buffer_key.resize(key_size);
        for (size_t j = 0; j < buffer_key.size(); j++) {
            buffer_key[j] = all_bytes(rng);
        }
        BlockCipher_u cipherA = implA(buffer_key.cmem());
        BlockCipher_u cipherB = implB(buffer_key.cmem());

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
