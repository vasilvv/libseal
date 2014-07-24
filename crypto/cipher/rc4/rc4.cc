#include "crypto/cipher/rc4.hh"

namespace crypto {

RC4Base_u RC4(const MemorySlice key, const MemorySlice iv) {
    return RC4Base_u(new RC4Impl(key, iv));
}

static inline void swap_bytes(uint8_t &a, uint8_t &b) {
    uint8_t tmp = a;
    a = b;
    b = tmp;
}

RC4Impl::RC4Impl(const MemorySlice key_mem, const MemorySlice iv_mem) {
    const uint8_t *key = key_mem.cptr();
    size_t key_len = key_mem.size();

    for (size_t k = 0; k < 256; k++) {
        S[k] = k;
    }

    uint8_t l = 0;
    for (size_t k = 0; k < 256; k++) {
        l = l + S[k] + key[k % key_len];
        swap_bytes(S[k], S[l]);
    }

    i = 0;
    j = 0;
}

void RC4Impl::stream_xor(MemorySlice stream) {
    for (size_t k = 0; k < stream.size(); k++) {
        uint8_t idx;
        i++;
        j += S[i];
        swap_bytes(S[i], S[j]);
        idx = S[i] + S[j];
        stream.ptr()[k] ^= S[idx];
    }
}

}
