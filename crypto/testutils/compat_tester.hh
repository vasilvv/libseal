#ifndef __CRYPTO_TESTUTILS_COMPAT_TESTER_HH
#define __CRYPTO_TESTUTILS_COMPAT_TESTER_HH

#include "crypto/cipher.hh"

namespace crypto {

/**
 * Test that block ciphers A and B can mutually understand each other by
 * generating a stream of random plaintext using a non-cryptographic RNG.
 */
void test_randomized_compat(BlockCipher *cipherA, BlockCipher *cipherB, uint32_t iters);

}

#endif /* __CRYPTO_TESTUTILS_COMPAT_TESTER__ */
