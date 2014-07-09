#include "crypto/cipher/aes.hh"
#include "crypto/cipher/aes/rijndael-alg-fst.h"

#include <cstdint>

#define MAX_AES_KEY_SCHEDULE_LEN   64

namespace crypto {

ReferenceAES::ReferenceAES() {
    enc_key_schedule.resize(MAX_AES_KEY_SCHEDULE_LEN);
    dec_key_schedule.resize(MAX_AES_KEY_SCHEDULE_LEN);
}

void ReferenceAES::set_key(const MemorySlice key) {
    // FIXME: assert key size
    key_size = key.size;

    rijndaelKeySetupEnc(&*enc_key_schedule.begin(), key.ptr, key_size * 8);
    rijndaelKeySetupDec(&*dec_key_schedule.begin(), key.ptr, key_size * 8);

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

}
