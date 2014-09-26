#ifndef __CRYPTO_BIGNUM_IMPL_BASIC_HH
#define __CRYPTO_BIGNUM_IMPL_BASIC_HH

namespace crypto {

template<size_t N>
void BNAdd_core(const uint64_t* x, const uint64_t* y, uint64_t* z, bool carryin, bool &carryout) {
    static_assert(N >= 64, "Bignum has to be 64-bit or larger");

    uint8_t carry = carryin;
    for (size_t i = 0; i < Bignum<N>::NW; i++) {
        uint64_t cur_x = x[i];
        uint64_t cur_y = y[i];

        z[i] = cur_x + cur_y + carry;
        carry = (z[i] < cur_x) | (((cur_x == UINT64_MAX) | (cur_y == UINT64_MAX)) & carry);
    }
    carryout = carry;
}

template<size_t N>
void BNAdd(const Bignum<N> &x, const Bignum<N> &y, Bignum<N> &output, bool carryin, bool &carryout) {
    BNAdd_core<N>(x.cdata64(), y.cdata64(), output.data64(), carryin, carryout);
}

template<size_t N>
void BNSub(const Bignum<N> &a, const Bignum<N> &b, Bignum<N> &output) {
    Bignum<N> tmp(b);
    bool discard;
    tmp.bin_inverse();
    BNAdd(a, tmp, output, 1, discard);
}

template<size_t N>
void BNSub_core(const uint64_t *a, const uint64_t *b, uint64_t *output) {
    static_assert(N >= 64, "Bignum has to be 64-bit or larger");

    Bignum<N> tmp(b);
    bool discard;
    tmp.bin_inverse();
    BNAdd(a, tmp, output, 1, discard);
}

}

#endif /* __CRYPTO_BIGNUM_IMPL_BASIC_HH */
