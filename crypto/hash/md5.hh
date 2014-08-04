#ifndef __CRYPTO_HASH_MD5_HH
#define __CRYPTO_HASH_MD5_HH

#include "crypto/hash.hh"

namespace crypto {

class MD5Base : public HashFunction {
  public:
    virtual const char *get_name() const override {
        return "MD5";
    }

    virtual size_t get_block_size() const override {
        return 64;
    }

    virtual size_t get_output_size() const override {
        return 16;
    }
};

typedef std::unique_ptr<MD5Base> MD5Base_u;
MD5Base_u MD5();

class MD5Impl : public MD5Base {
  private:
    unsigned int sz[2];
    uint32_t counter[4];
    uint8_t save[64];

    void calc(uint32_t *data);

  public:
    MD5Impl();

    virtual void update(const memslice data) override;
    virtual bytestring_u finish() override;
};

}

#endif /* __CRYPTO_HASH_MD5_HH */
