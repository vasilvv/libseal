#ifndef __CRYPTO_CIPHER_RC4_HH
#define __CRYPTO_CIPHER_RC4_HH

#include "crypto/cipher.hh"

namespace crypto {

/**
 * Base class for various implementations of RC4.
 */
class RC4Base : public StreamCipher {
  public:
    virtual ~RC4Base() {};

    virtual const char *get_name() const override {
        return "RC4";
    }

    virtual bool is_valid_key_size(size_t size) const override {
        return size >= 1 && size <= 256;
    }
};

typedef std::unique_ptr<RC4Base> RC4Base_u;
RC4Base_u RC4(const memslice key, const memslice iv);

/**
 * Straightforward implementation of RC4 in pure C.
 */
class RC4Impl : public RC4Base {
  private:
    uint8_t i;
    uint8_t j;
    uint8_t S[256];
  public:
    virtual const char *get_impl_desc() const override { return "RC4 (standard)"; }

    RC4Impl(const memslice key, const memslice iv);
    virtual void stream_xor(memslice stream) override;
};

};

#endif /* __CRYPTO_CIPHER_RC4_HH */
