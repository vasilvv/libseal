#include "crypto/cipher.hh"

namespace crypto {

void BlockCipher::encrypt_cbc(const bytestring &plaintext, const bytestring &iv,
                              bytestring &ciphertext) const {
    // FIXME: assert the right size of IV
    // FIXME: assert that block size is proportional
    size_t block_size = get_block_size();
    size_t num_blocks = plaintext.size() / block_size;
    ciphertext.resize(num_blocks * block_size);

    if (num_blocks == 0) {
        return;
    }

    bytestring buffer(iv);
    for (size_t i = 0; i < num_blocks; i++) {
        // XOR previous ciphertext or IV with new plaintext
        for (size_t j = 0; j < block_size; j++) {
            buffer[j] ^= plaintext[i * block_size + j];
        }

        // Actually encrypt the block
        uint8_t *current_ciphertext = ciphertext.ptr() + i * block_size;
        encrypt_block(buffer.ptr(), current_ciphertext);

        // Copy ciphertext to the next buffer
        buffer.copy_from(mem(current_ciphertext, block_size));
    }
}

void BlockCipher::decrypt_cbc(const bytestring &ciphertext, const bytestring &iv,
                              bytestring &plaintext) const {
    // FIXME: assert the right size of IV
    // FIXME: assert that block size is proportional
    size_t block_size = get_block_size();
    size_t num_blocks = ciphertext.size() / block_size;
    plaintext.resize(num_blocks * block_size);

    if (num_blocks == 0) {
        return;
    }

    for (size_t i = 0; i < num_blocks; i++) {
        const uint8_t *prev_ciphertext;
        uint8_t *target_plaintext = plaintext.ptr() + i * block_size;

        // Select previous ciphertext or IV to XOR with
        if (i > 0) {
            prev_ciphertext = ciphertext.cptr() + (i - 1) * block_size;
        } else {
            prev_ciphertext = iv.cptr();
        }

        // Decrypt
        decrypt_block(ciphertext.cptr() + i * block_size, target_plaintext);

        // XOR previous ciphertext or IV with the plaintext
        for (size_t j = 0; j < block_size; j++) {
            target_plaintext[j] ^= prev_ciphertext[j];
        }
    }
}

}
