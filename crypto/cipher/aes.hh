#ifndef __CRYPTO_CIPHER_AES_HH
#define __CRYPTO_CIPHER_AES_HH

#include "crypto/cipher.hh"

#include <vector>

namespace crypto {

class AESBase : public BlockCipher {
    virtual const char *get_name() const override {
        return "AES";
    }

    virtual size_t get_block_size() const override {
        return 16;
    }

    virtual bool is_valid_key_size(size_t size) const override {
        return (size == 16) || (size == 32);
    }
};

typedef std::unique_ptr<AESBase> AESBase_u;

AESBase_u getAESImplementation();

class ReferenceAES : public AESBase {
  private:
    std::vector<uint32_t> enc_key_schedule;
    std::vector<uint32_t> dec_key_schedule;

    size_t key_size;
    uint8_t nrounds;

  public:
    ReferenceAES();

    virtual const char *get_impl_desc() const override {
        return "Reference AES implementation";
    }

    virtual void set_key(const MemorySlice key) override;
    virtual void encrypt_block(const uint8_t *plaintext,
                               uint8_t *ciphertext) const override;
    virtual void decrypt_block(const uint8_t *ciphertext,
                               uint8_t *plaintext) const override;
};

}

#endif /* __CRYPTO_CIPHER_AES_HH */
