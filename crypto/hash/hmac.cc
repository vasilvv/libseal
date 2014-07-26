#include "crypto/hash.hh"

#include <cstring>

namespace crypto {

template <uint8_t padding>
static inline void copy_and_pad(const MemorySlice in_mem, MemorySlice out_mem) {
    size_t i = 0;
    const uint8_t *in = in_mem.cptr();
    uint8_t *out = out_mem.ptr();

    for (; i < in_mem.size(); i++) {
        out[i] = in[i] ^ padding;
    }

    for (; i < out_mem.size(); i++) {
        out[i] = padding;
    }
}

HMAC::HMAC(HashFunctionFactory HFF, const MemorySlice key) {
    inner_hash = HFF();
    outer_hash = HFF();

    size_t block_size = inner_hash->get_block_size();
    bytestring inner_padded_key(block_size);
    bytestring outer_padded_key(block_size);

    if (key.size() > block_size) {
        bytestring_u real_key = hash(HFF, key);
        copy_and_pad<0x36>(real_key->cmem(), inner_padded_key.mem());
        copy_and_pad<0x5c>(real_key->cmem(), outer_padded_key.mem());
    } else {
        copy_and_pad<0x36>(key, inner_padded_key.mem());
        copy_and_pad<0x5c>(key, outer_padded_key.mem());
    }

    inner_hash->update(inner_padded_key.cmem());
    outer_hash->update(outer_padded_key.cmem());
}

void HMAC::update(const MemorySlice data) {
    inner_hash->update(data);
}

bytestring_u HMAC::finish() {
    bytestring_u inner_hash_value = inner_hash->finish();
    outer_hash->update(inner_hash_value->cmem());
    return outer_hash->finish();
}

}
