/**
 * Copyright (C) 2014 The PonySSL Authors.  All rights reservied.
 *
 * Use of this source code file is governed by MIT license, as stated in the
 * LICENSE file.
 */
#ifndef __CRYPTO_CIPHER_HH
#define __CRYPTO_CIPHER_HH

#include <cstdint>
#include <cstddef>

#include "crypto/common.hh"

namespace crypto {

/**
 * Common methods for both BlockCipher and StreamCipher interface.
 */
class CipherBase {
  public:
    virtual ~CipherBase() {};

    /**
     * Return the name of the cipher algorithm, like "AES" or "Chacha20".
     */
    virtual const char *get_name() const = 0;

    /**
     * Return the descriptive name of AES implementation, like "AES-NI"
     * or "VPAES".
     */
    virtual const char *get_impl_desc() const = 0;

    /**
     * Returns true if the block cipher works with keys of |size|
     * size.
     */
    virtual bool is_valid_key_size(size_t size) const = 0;
};

/**
 * The base interface which is implemented by every cipher which operates on
 * blocks of fixed size.  Note that "fixed size" here means that each subclass
 * has fixed size.
 */
class BlockCipher : public CipherBase {
  public:
    virtual ~BlockCipher() {};

    /**
     * Set and schedule the key for subsequent operations.
     */
    virtual void set_key(const MemorySlice key) = 0;

    /**
     * Return the size of the block on which the class operates.
     */
    virtual size_t get_block_size() const = 0;

    /**
     * Encrypt block of size returned by get_block_size() worth of bytes
     * pointed by |plaintext|, and put the result into the memory pointed by
     * |ciphertext| using key stored in |key|.
     *
     * The |key| has to be set using set_key() before this function may be
     * invoked.
     */
    virtual void encrypt_block(const uint8_t *plaintext,
                               uint8_t *ciphertext) const = 0;
    /**
     * Encrypt block of size returned by get_block_size() worth of bytes
     * pointed by |plaintext|,and put the result into the memory pointed by
     * |ciphertext| using key stored in |key|.
     *
     * The |key| has to be set using set_key() before this function may be
     * invoked.
     */
    virtual void decrypt_block(const uint8_t *ciphertext,
                               uint8_t *plaintext) const = 0;

    /**
     * CBC mode encryption.
     *
     * Encrypt specified chunk of plaintext using key and the specified IV.
     * Does not handle padding; plaintext MUST be divisible by the block size
     * and the IV length MUST be equal to the block size.
     */
    virtual void encrypt_cbc(const bytestring &plaintext, const bytestring &iv,
            bytestring &ciphertext) const;

    /**
     * CBC mode decryption.
     *
     * Decrypt specified block of ciphertext using key and the specified IV.
     * Does not handle padding; ciphertext MUST be divisible by the block size
     * and the IV length MUST be equal to the block size.
     */
    virtual void decrypt_cbc(const bytestring &ciphertext, const bytestring &iv,
            bytestring &plaintext) const;

    /**
     * CTR mode encryption/decryption.
     *
     * 
     */
    //virtual void counter_xor(const bytestring &iv, const bytestring &input,
                     //bytestring &output) const;
};

/**
 * The base interface of a stream cipher, that is, a cipher which operates by
 * generating a random stream of bytes based on the key and IV, and encrypts
 * data by XORing it with that stream.
 */
class StreamCipher : public CipherBase {
  public:
    virtual ~StreamCipher() {};

    /**
     * Generate the initial state of the stream cipher based on the
     * supplied key and initialization vector.
     */
    virtual void init(const MemorySlice key, const MemorySlice iv) = 0;

    /**
     * Generate the secret stream and xor it with the contents of the supplied
     * memory slice.
     */
    virtual void stream_xor(MemorySlice stream) = 0;
};

}

#endif /* __CRYPTO_CIPHER_HH */
