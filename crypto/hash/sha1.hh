#ifndef __CRYPTO_HASH_SHA1_HH
#define __CRYPTO_HASH_SHA1_HH

#include "crypto/hash.hh"

namespace crypto {

class SHA1Base : public HashFunction {
  public:
    virtual const char *get_name() const override {
        return "SHA1";
    }

    virtual size_t get_block_size() const override {
        return 64;
    }

    virtual size_t get_output_size() const override {
        return 16;
    }
};

typedef std::unique_ptr<SHA1Base> SHA1Base_u;
SHA1Base_u SHA1();

class SHA1Impl : public SHA1Base {
  private:
    unsigned int sz[2];
    uint32_t counter[5];
    uint8_t save[64];

    void calc(uint32_t *data);

  public:
    SHA1Impl();

    virtual void update(const MemorySlice data) override;
    virtual bytestring_u finish() override;
};

}

#endif /* __CRYPTO_HASH_SHA1_HH */
