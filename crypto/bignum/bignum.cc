#include "crypto/bignum.hh"

namespace crypto {

AnyBignum_u bignum_from_binary(const memslice mem) {
    if (mem.size() <= 8) {
        return AnyBignum_u(new Bignum<64>(mem));
    }
    if (mem.size() <= 16) {
        return AnyBignum_u(new Bignum<128>(mem));
    }
    if (mem.size() <= 32) {
        return AnyBignum_u(new Bignum<256>(mem));
    }
    if (mem.size() <= 64) {
        return AnyBignum_u(new Bignum<512>(mem));
    }
    if (mem.size() <= 128) {
        return AnyBignum_u(new Bignum<1024>(mem));
    }
    if (mem.size() <= 256) {
        return AnyBignum_u(new Bignum<2048>(mem));
    }
    if (mem.size() <= 512) {
        return AnyBignum_u(new Bignum<4096>(mem));
    }
    if (mem.size() <= 1024) {
        return AnyBignum_u(new Bignum<8192>(mem));
    }

    return nullptr;
}

AnyBignum_u bignum_from_binary_exact(const memslice mem) {
    AnyBignum_u bn = bignum_from_binary(mem);
    if (!bn) {
        return nullptr;
    }
    if (mem.size() != bn->len_bytes()) {
        return nullptr;
    }
    return bn;
}

AnyBignum_u bignum_from_hex_exact(std::string hex) {
    AnyBignum_u bn;
    switch (hex.size()) {
        case 16:
            bn.reset(new Bignum<64>());
            break;
        case 32:
            bn.reset(new Bignum<128>());
            break;
        case 64:
            bn.reset(new Bignum<256>());
            break;
        case 128:
            bn.reset(new Bignum<512>());
            break;
        case 256:
            bn.reset(new Bignum<1024>());
            break;
        case 512:
            bn.reset(new Bignum<2048>());
            break;
        case 1024:
            bn.reset(new Bignum<4096>());
            break;
        case 2048:
            bn.reset(new Bignum<8192>());
            break;
        default:
            return nullptr;
    }
    bn->from_hex(hex);
    return bn;
}

}
