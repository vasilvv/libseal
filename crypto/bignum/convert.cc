#include "crypto/bignum.hh"

namespace crypto {

/**
 * Constant-time conversion of [0, 16) range into appropriate ASCII character
 * hex representation.
 */
static inline char digit_to_hex(uint8_t n) {
    char alphabet_offset_mask = -(n > 9);
    return n + '0' + (('a' - '0' - 10) & alphabet_offset_mask);
}

/**
 * Predicate which checks if the character can be part of hexadecimal string.
 */
static inline bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}


std::string Bignum::to_hex() const {
    const size_t NB = bytelen;
    std::string result;
    result.resize(NB * 2);
    for (size_t i = 0; i < NB; i++) {
        result[2*i]   = digit_to_hex(data[NB-i-1] >> 4);
        result[2*i+1] = digit_to_hex(data[NB-i-1] & 0x0f);
    }
    return result;
}

bool Bignum::from_hex(const memslice src) {
    if (src.size() != data.size() * 2) {
        return false;
    }

    if (!std::all_of(src.ccharptr(), src.ccharptr() + src.size(), is_hex_char)) {
        return false;
    }


    bytestring orig = bytestring::from_hex(src);
    std::copy(orig.crbegin(), orig.crend(), data.begin());

    return true;
}

}
