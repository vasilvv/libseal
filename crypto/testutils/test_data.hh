#ifndef __CRYPTO_TESTUTILS_COMPAT_TESTER_HH
#define __CRYPTO_TESTUTILS_COMPAT_TESTER_HH

#include <string>

namespace crypto {

/**
 * Returns the path where the test data is stored.  In our setup, this is the
 * same directory as the binary where it was launched.  In case of failure,
 * returns an empty string.
 */
std::string test_data_path(std::string test_data_file);

}

#endif /* __CRYPTO_TESTUTILS_COMPAT_TESTER__ */
