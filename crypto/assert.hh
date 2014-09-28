#ifndef __CRYPTO_ASSERT_HH
#define __CRYPTO_ASSERT_HH

#include <cassert>

namespace crypto {

/**
 * Generic assertion for sanity-checking.  Should fail only if an impossible
 * condition is reached.
 */
inline void sanity_assert(bool assertion) {
    assert(assertion);
}

/**
 * Assertion for the cases where program uses a module while violating its
 * interface contract.
 */
inline void contract_assert(bool assertion) {
    assert(assertion);
}

};

#endif  /* __CRYPTO_ASSERT_HH */
