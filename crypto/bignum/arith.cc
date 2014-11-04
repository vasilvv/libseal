#include "crypto/bignum.hh"

namespace crypto {

/*******************  Simple operations  *******************/

void Bignum::bin_inverse() {
    for (size_t i = 0; i < wordlen; i++) {
        words()[i] = ~words()[i];
    }
}

void Bignum::zero() {
    for (size_t i = 0; i < wordlen; i++) {
        words()[i] = 0;
    }
}

/*******************  Comparison  *******************/

/**
 * Determine whether |a| is less than |b| in constant-time.
 */
bool Bignum::lt_raw(size_t bytelen, const bnword_t *a, const bnword_t *b) {
    const size_t wordlen = bytelen / sizeof(bnword_t);

    bnword_t mask = 1;
    bnword_t answer = 0;
    // Iterate over number in big-endian order
    for (size_t i = 0; i < wordlen; i++) {
        bnword_t this_word = a[wordlen - i - 1];
        bnword_t other_word = b[wordlen - i - 1];

        // Put the results of comparison into the answer
        answer += mask & (this_word < other_word);
        // Unless this one was equal, we already got the answer; set mask to
        // zero
        mask = mask & (this_word == other_word);
    }
    return answer;
}

/*******************  Shifts  *******************/

/**
 * Shift left the big number by one bit.  Works when input and output point to
 * the same address in memory.
 */
void Bignum::shl1_raw(size_t bytelen, const bnword_t *input, bnword_t *output) {
    const size_t wordlen = bytelen / sizeof(bnword_t);

    bnword_t carry_bit = 0;
    for (size_t i = 0; i < wordlen; i++) {
        bnword_t next_carry_bit = input[i] >> (sizeof(bnword_t) * 8 - 1);

        output[i] = (input[i] << 1) | carry_bit;
        carry_bit = next_carry_bit;
    }
}

/**
 * Shift right the big number by one bit.  Works when input and output point to
 * the same address in memory.
 */
void Bignum::shr1_raw(size_t bytelen, const bnword_t *input, bnword_t *output) {
    const size_t wordlen = bytelen / sizeof(bnword_t);

    bnword_t carry_bit = 0;
    for (size_t i_real = 0; i_real < wordlen; i_real++) {
        size_t i = wordlen - i_real - 1;
        bnword_t next_carry_bit = input[i] & 0x01;
        next_carry_bit = next_carry_bit << (sizeof(bnword_t) * 8 - 1);

        output[i] = (input[i] >> 1) | carry_bit;
        carry_bit = next_carry_bit;
    }
}

/*******************  Addition and subtraction  *******************/

/**
 * Compute x + y + carryin, put the result into z, put carry-out into carryout.
 * z is allowed to be either x or y.
 */
void Bignum::add_raw(size_t bytelen, const bnword_t *x, const bnword_t *y,
                     bnword_t *z, bool carryin, bool &carryout) {
    const size_t wordlen = bytelen / sizeof(bnword_t);

    uint8_t carry = carryin;
    for (size_t i = 0; i < wordlen; i++) {
        bnword_t cur_x = x[i];
        bnword_t cur_y = y[i];

        z[i] = cur_x + cur_y + carry;
        carry = (z[i] < cur_x) |
                (((cur_x == BNWORD_MAX) | (cur_y == BNWORD_MAX)) & carry);
    }
    carryout = carry;
}

/**
 * Subtract y from x.
 */
void Bignum::sub_raw(size_t bytelen, const bnword_t *x, const bnword_t *y,
                     bnword_t *output) {
    Bignum tmp(bytelen);
    std::copy(y, y + (bytelen / sizeof(bnword_t)), tmp.words());

    bool discard;
    tmp.bin_inverse();
    add_raw(bytelen, x, tmp.cwords(), output, 1, discard);
}

std::unique_ptr<Bignum> Bignum::add_to(const Bignum &other, bool carryin,
                                       bool &carryout) {
    const size_t result_len = std::max(bytelen, other.bytelen);
    this->autopromote(result_len);
    other.autopromote(result_len);

    std::unique_ptr<Bignum> result(new Bignum(result_len));
    add_raw(result_len, cwords(), other.cwords(), result->words(), carryin,
            carryout);
    return result;
}

void Bignum::increase_by(const Bignum &other, bool carryin, bool &carryout) {
    other.autopromote(bytelen);
    add_raw(bytelen, cwords(), other.cwords(), words(), carryin,
                   carryout);
}

void Bignum::decrease_by(const Bignum &other) {
    other.autopromote(bytelen);
    sub_raw(bytelen, cwords(), other.cwords(), words());
}

/*******************  Multiplication  *******************/

/**
 * The function below does the following.  It takes two arguments of type
 * bnword_t, and multiplies them together in order to get result of twice
 * larger size.
 *
 * It employs the following approach:
 *   a * b = (a_0 + B * a_1) (b_0 + B * b_1)
 *         = a_0 b_0 + B (a_0 b_1 + a_1 b_0) + B^2 a_1 b_1
 * where B is 2^(# of bits / 2).
 */
void Bignum::mul_bnword(const bnword_t a, const bnword_t b,
                        bnword_half_t *output /*[4]*/) {
    const bnword_t a_lower = (a & BNWORD_HALF_MAX);
    const bnword_t b_lower = (b & BNWORD_HALF_MAX);
    const bnword_t a_higher = (a >> (sizeof(bnword_half_t) * 8));
    const bnword_t b_higher = (b >> (sizeof(bnword_half_t) * 8));

    bnword_t *output_lower = reinterpret_cast<bnword_t *>(output);
    bnword_t *output_higher = reinterpret_cast<bnword_t *>(output + 2);

    // Add x_0 * y_0 and x_1 * y_1 * b^2
    *output_lower = a_lower * b_lower;
    *output_higher = a_higher * b_higher;

    // We need to add the middle factors now, but the problem is, we can't just
    // add them, because there might be a carry issue.  So we create two
    // numbers of the output size...
    bnword_half_t arg1[4] = { 0, 0, 0, 0 };
    bnword_half_t arg2[4] = { 0, 0, 0, 0 };

    // ...set them to b x_1 y_0 and b x_0 y_1...
    *((bnword_t *)(arg1 + 1)) = a_higher * b_lower;
    *((bnword_t *)(arg2 + 1)) = a_lower * b_higher;

    // ...and add the resulting numbers to the output
    bool discard;
    add_raw(sizeof(arg1), output_lower, reinterpret_cast<bnword_t *>(arg1),
            output_lower, 0, discard);
    add_raw(sizeof(arg2), output_lower, reinterpret_cast<bnword_t *>(arg2),
            output_lower, 0, discard);
}

/**
 * Full-featured Karatsuba multiplication.  This takes the input of size N, and
 * produces output of size 2N.
 *
 * The short idea of how this works is explained here:
 *     https://gmplib.org/manual/Karatsuba-Multiplication.html
 * You should look at that diagram closely if you want to understand how the
 * method below works.  Also, the method above is essentially a "baby version"
 * of this.
 *
 * Let B = 2^(# of bits in a word), a = (a_l + B * a_h), b = (b_l + B * b_h).
 * In the algorithm below,
 *     z_0 = a_l * b_l
 *     z_2 = a_h * b_h
 *     z_1 = (a_h - a_l)(b_h - b_l)
 *     a * b = z_0 + B^2 z_2 + B (z_2 + z_0 - z_1)
 */
void Bignum::mul_raw(size_t bytelen, const bnword_t *a /*[N]*/,
                     const bnword_t *b /*[N]*/, bnword_t *output /*[2N]*/) {
    sanity_assert(bytelen >= sizeof(bnword_t));

    // Base case of the recursion.  We can't recurse any further, so just
    // multiply numbers using hardware.
    if (bytelen == sizeof(bnword_t)) {
#ifdef HAVE_INT128
        // Intel CPUs can multiply two 64-bit numbers and return a 32-bit one.
        // If we have a GCC extension which allows us to take advantage of
        // this, use it
        unsigned __int128 result =
            (unsigned __int128)(*a) * (unsigned __int128)(*b);
        output[0] = (uint64_t)result;
        output[1] = result >> 64;
#else
        // Otherwise, reduce to half-word version
        mul_bnword(*a, *b, reinterpret_cast<bnword_half_t *>(output));
#endif /* HAVE_INT128 */
        return;
    }

    // Helper constants
    const size_t subbytelen = bytelen / 2;
    const size_t wordlen = bytelen / sizeof(bnword_t);
    const size_t subwordlen = wordlen / 2;
    bnword_t *output_higher = output + wordlen;
    const bnword_t *a_lower = a;
    const bnword_t *b_lower = b;
    const bnword_t *a_higher = a + subwordlen;
    const bnword_t *b_higher = b + subwordlen;
    bool discard;

    // FIXME: we may need a malloc here, or a preallocated buffer, for stack
    // integrity reasons (VLAs are non-standard and essentially alloca()).

    // z_0 = a_l * b_l
    // z_2 = a_h * b_h
    // z_0_full = z_0 * B, same for z_2_full
    bnword_t z0_full[2 * wordlen];
    bnword_t z2_full[2 * wordlen];
    memset(z0_full, 0, 2 * bytelen);
    memset(z2_full, 0, 2 * bytelen);
    bnword_t *z0 = z0_full + subwordlen;
    bnword_t *z2 = z2_full + subwordlen;
    mul_raw(subbytelen, a_lower, b_lower, z0);
    mul_raw(subbytelen, a_higher, b_higher, z2);

    // z_1 = (a_h - a_l) * (b_h - b_l)
    bnword_t z1_full[2 * wordlen];
    memset(z1_full, 0, 2 * bytelen);
    bnword_t *z1 = z1_full + subwordlen;
    bnword_t z1_arg1[subwordlen];
    bnword_t z1_arg2[subwordlen];
    memset(z1_arg1, 0, 2 * subbytelen);
    memset(z1_arg2, 0, 2 * subbytelen);

    // Here we do the manual bookkeeping of z_1 sign
    bool diff1_positive = !lt_raw(subbytelen, a_higher, a_lower);
    bool diff2_positive = !lt_raw(subbytelen, b_higher, b_lower);
    bool z1_positive = !(diff1_positive xor diff2_positive);

    // FIXME: constant-time swap of arguments instead of branches
    if (diff1_positive) {
        sub_raw(subbytelen, a_higher, a_lower, z1_arg1);
    } else {
        sub_raw(subbytelen, a_lower, a_higher, z1_arg1);
    }
    if (diff2_positive) {
        sub_raw(subbytelen, b_higher, b_lower, z1_arg2);
    } else {
        sub_raw(subbytelen, b_lower, b_higher, z1_arg2);
    }
    mul_raw(subbytelen, z1_arg1, z1_arg2, z1);

    // a * b = b^2 z2 + z0 + b (z2 + z0 - z1)
    std::copy(z0, z0 + wordlen, output);
    std::copy(z2, z2 + wordlen, output_higher);
    add_raw(2 * bytelen, z2_full, output, output, false, discard);
    add_raw(2 * bytelen, z0_full, output, output, false, discard);
    // FIXME: replace with constant-time cosntruct
    if (z1_positive) {
        sub_raw(2 * bytelen, output, z1_full, output);
    } else {
        add_raw(2 * bytelen, output, z1_full, output, false, discard);
    }
}

std::unique_ptr<Bignum> Bignum::multiply_by(const Bignum &other) {
    const size_t arg_len = std::max(bytelen, other.bytelen);
    this->autopromote(arg_len);
    other.autopromote(arg_len);

    std::unique_ptr<Bignum> result(new Bignum(2 * arg_len));
    mul_raw(arg_len, cwords(), other.cwords(), result->words());
    return result;
}

}
