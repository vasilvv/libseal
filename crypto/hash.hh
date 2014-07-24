#ifndef __CRYPTO_HASH_HH
#define __CRYPTO_HASH_HH

#include "crypto/common.hh"

#include <functional>

namespace crypto {

/**
 * Common interface for all hash functions.  The data is inputted by calling
 * update(); calling finish() causes the hash for all data inputted so far to
 * be returned.
 */
class HashFunction {
  public:
    virtual ~HashFunction() {};

    /**
     * The name of the hash function, like "MD5" or "SHA2-256".
     */
    virtual const char *get_name() const = 0;

    /**
     * The block size on which the hash function operates. Necessary in order
     * to use the hash function for the HMAC construction.
     */
    virtual size_t get_block_size() const = 0;

    /**
     * Return the length of hash function's output.
     */
    virtual size_t get_output_size() const = 0;

    /**
     * Feed data into the hash function.
     */
    virtual void update(const MemorySlice data) = 0;

    /**
     * Finish computation of the hash function and return the output.  May
     * change the state of the hash, so, if hash needs to be continued later,
     * the caller should copy the hash state into another object.
     */
    virtual bytestring_u finish() = 0;
};

typedef std::unique_ptr<HashFunction> HashFunction_u;
typedef std::function<HashFunction_u()> HashFunctionFactory;

inline bytestring_u hash(HashFunctionFactory HFF, const MemorySlice data) {
    HashFunction_u hash = HFF();
    hash->update(data);
    return hash->finish();
}

}

#endif /* __CRYPTO_HASH_HH */
