#include "crypto/cpu.hh"
#include "crypto/cipher/aes.hh"
#include "crypto/cipher/aes/rijndael-alg-fst.h"

#include "iaesni.h"

#include <cstdint>

#define MAX_AES_KEY_SCHEDULE_LEN   64

namespace crypto {

AESBase_u AES(const MemorySlice key) {
    CPU cpu;

    if (cpu.has_aesni()) {
        return AESBase_u(new IntelAES(key));
    }

    return AESBase_u(new ReferenceAES(key));
}

ReferenceAES::ReferenceAES(const MemorySlice key) {
    enc_key_schedule.resize(MAX_AES_KEY_SCHEDULE_LEN);
    dec_key_schedule.resize(MAX_AES_KEY_SCHEDULE_LEN);

    // FIXME: assert key size
    key_size = key.size();

    rijndaelKeySetupEnc(&*enc_key_schedule.begin(), key.cptr(), key_size * 8);
    rijndaelKeySetupDec(&*dec_key_schedule.begin(), key.cptr(), key_size * 8);

    if (key_size == 16) {
        nrounds = 10;
    }
    if (key_size == 32) {
        nrounds = 14;
    }
}

void ReferenceAES::encrypt_block(const uint8_t *plaintext,
                                 uint8_t *ciphertext) const {
    rijndaelEncrypt(enc_key_schedule.data(), nrounds, plaintext, ciphertext);
}

void ReferenceAES::decrypt_block(const uint8_t *ciphertext,
                                 uint8_t *plaintext) const {
    rijndaelDecrypt(dec_key_schedule.data(), nrounds, ciphertext, plaintext);
}


IntelAES::IntelAES(const MemorySlice key) {
    secret_key = bytestring(key);
}

void IntelAES::encrypt_block(const uint8_t *plaintext,
                             uint8_t *ciphertext) const {
    if (secret_key.size() == 16) {
        intel_AES_enc128(const_cast<uint8_t *>(plaintext), ciphertext,
                         const_cast<uint8_t *>(secret_key.cptr()), 1);
    }
    if (secret_key.size() == 32) {
        intel_AES_enc256(const_cast<uint8_t *>(plaintext), ciphertext,
                         const_cast<uint8_t *>(secret_key.cptr()), 1);
    }
}

void IntelAES::decrypt_block(const uint8_t *ciphertext,
                                 uint8_t *plaintext) const {
    if (secret_key.size() == 16) {
        intel_AES_dec128(const_cast<uint8_t *>(ciphertext), plaintext,
                         const_cast<uint8_t *>(secret_key.cptr()), 1);
    }
    if (secret_key.size() == 32) {
        intel_AES_dec256(const_cast<uint8_t *>(ciphertext), plaintext,
                         const_cast<uint8_t *>(secret_key.cptr()), 1);
    }
}

void IntelAES::encrypt_cbc(const bytestring &plaintext, const bytestring &iv,
                           bytestring &ciphertext) const {
    size_t num_blocks = plaintext.size() / get_block_size();
    ciphertext.resize(plaintext.size());

    if (secret_key.size() == 16) {
        intel_AES_enc128_CBC(const_cast<uint8_t *>(plaintext.cptr()),
                             ciphertext.ptr(),
                             const_cast<uint8_t *>(secret_key.cptr()),
                             num_blocks, const_cast<uint8_t *>(iv.cptr()));
    }
    if (secret_key.size() == 32) {
        intel_AES_enc256_CBC(const_cast<uint8_t *>(plaintext.cptr()),
                             ciphertext.ptr(),
                             const_cast<uint8_t *>(secret_key.cptr()),
                             num_blocks, const_cast<uint8_t *>(iv.cptr()));
    }
}

void IntelAES::decrypt_cbc(const bytestring &ciphertext, const bytestring &iv,
            bytestring &plaintext) const {
    size_t num_blocks = ciphertext.size() / get_block_size();
    plaintext.resize(ciphertext.size());

    if (secret_key.size() == 16) {
        intel_AES_dec128_CBC(const_cast<uint8_t *>(ciphertext.cptr()),
                             plaintext.ptr(),
                             const_cast<uint8_t *>(secret_key.cptr()),
                             num_blocks, const_cast<uint8_t *>(iv.cptr()));
    }
    if (secret_key.size() == 32) {
        intel_AES_dec256_CBC(const_cast<uint8_t *>(ciphertext.cptr()),
                             plaintext.ptr(),
                             const_cast<uint8_t *>(secret_key.cptr()),
                             num_blocks, const_cast<uint8_t *>(iv.cptr()));
    }
}

}
