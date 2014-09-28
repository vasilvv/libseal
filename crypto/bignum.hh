#ifndef __CRYPTO_BIGNUM_HH
#define __CRYPTO_BIGNUM_HH

#include "crypto/common.hh"

#include <algorithm>
#include <cstring>
#include <memory>

namespace crypto {

#if UINTPTR_MAX == UINT32_MAX
// 32-bit
static_assert(sizeof(void *) == 4, "Plaform word size detection failed");
typedef uint32_t bnword_t;
typedef uint16_t bnword_half_t;
#define BNWORD_MAX   UINT32_MAX
#define BNWORD_HALF_MAX   UINT16_MAX

#elif UINTPTR_MAX == UINT64_MAX
// 64-bit

// __int128 is a 128-bit integer type which allows us to use that nice feature
// of Intel CPUs where you can get full 128-result from multiplying 64-bit
// numbers.  Unfortunately, both GCC and Clang screwed this up at some point.
// This checks version for GCC;  Clang refuses to have reasonable way to check
// for version (because they expect you to use has_feature macro -- too bad
// there is not has_not_screwed_up()), so we limit ourselves to check whether
// the type even exists, and if not, hope that tests will catch this.
#if defined(__GNUC__) && \
    ((defined(__clang__) && defined(__SIZEOF_INT128__)) || \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 6)))
#define HAVE_INT128
#endif

static_assert(sizeof(void *) == 8, "Plaform word size detection failed");
typedef uint64_t bnword_t;
typedef uint32_t bnword_half_t;
#define BNWORD_MAX   UINT64_MAX
#define BNWORD_HALF_MAX   UINT32_MAX

#else
// Something else
#error  "The system has to be at least 32-bit"
#endif

constexpr static bool is_power_of_two(size_t n) {
    return n == 2 || (!(n & 1) ? is_power_of_two(n / 2) : false);
}

/**
 * Unsigned arbitrary precision arithmetic class for cryptographic purposes.
 *
 * One of the important features of this Bignum is that while the contents of
 * it is mutable, the *size* is fixed and has to be power of two.
 *
 * Most operations are designed to be constant-time.  Some operations (like
 * parsing hexadecimal representantion) do not provide such obligation,
 * primarily those which might fail.
 */
class Bignum {
  protected:
    // When an arithmetic operation is performed on values of different sizes,
    // data[] is automatically padded with zeroes before the result is passed
    // into arithmetic function;  this does not actually change the value of
    // the bignum, since the real length is bytelen.
    mutable bytestring data;

    /**
     * Return the data represented in the word size we use.
     */
    inline bnword_t *words() {
        return reinterpret_cast<bnword_t *>(data.ptr());
    }
    /**
     * Const variant of words().
     */
    inline const bnword_t *cwords() const {
        return reinterpret_cast<const bnword_t *>(data.cptr());
    }

    /**
     * Pad internal data buffer to the size of new_bytes.  Works with
     * constant-size objects.
     */
    inline void autopromote(size_t new_bytes) const {
        if (bytelen < new_bytes) {
            data.resize(new_bytes);
        }
    }

    // Internal raw methods
    static void add_raw(size_t bytelen, const bnword_t *x, const bnword_t *y,
                        bnword_t *z, bool carryin, bool &carryout);
    static void sub_raw(size_t bytelen, const bnword_t *x, const bnword_t *y,
                        bnword_t *output);
    static bool lt_raw(size_t bytelen, const bnword_t *a, const bnword_t *b);
    static void mul_bnword(const bnword_t a, const bnword_t b, bnword_half_t *output /*[4]*/);
    static void mul_raw(size_t bytelen, const bnword_t *a /*[N]*/,
                        const bnword_t *b /*[N]*/, bnword_t *output /*[2N]*/);

  public:
    // Size in bytes
    const size_t bytelen;
    // Size in words
    const size_t wordlen;

    /**
     * Initialze the big number of |bytes| size.  |bytes| has to be a power of
     * two.
     */
    inline Bignum(size_t bytes)
        : data(bytes), bytelen(bytes), wordlen(bytes / sizeof(bnword_t)) {
        contract_assert(is_power_of_two(bytes));
        contract_assert(bytes >= sizeof(bnword_t));
    }

    /**
     * Initialze the big number of |bytes| size.  |bytes| has to be a power of
     * two.  Initializes it with a supplied 32-bit value (32-bit because that
     * is the minimal supported byte size.
     */
    inline Bignum(size_t bytes, uint32_t value) : Bignum(bytes) {
        data[0] = value;
    }

    /**
     * Convert the big-number to the padded hexadecimal representation.
     */
    std::string to_hex() const;

    /**
     * Convert from a hexadecimal string.  Returns false if the string is
     * malformed.
     */
    inline bool from_hex(std::string &str) {
        return from_hex(cmem(str.data(), str.size()));
    }

    /**
     * Convert from a hexadecimal string.  Returns false if the string is
     * malformed.
     */
    inline bool from_hex(const char *str) {
        return from_hex(cmem(str, strlen(str)));
    }

    /**
     * Convert from a hexadecimal string.  Returns false if the string is
     * malformed.
     */
    bool from_hex(const memslice src);

    /**
     * In-place binary inversion of the bignum.
     */
    void bin_inverse();

    /**
     * Zeroes the number.
     */
    void zero();

    /**
     * Test if all digits are zeroes.
     */
    inline explicit operator bool() const {
        bool result = false;
        for (size_t i = 0; i < wordlen; i++) {
            result |= cwords()[i];
        }
        return result;
    }

    /**
     * Constant-type inequality test.
     */
    inline bool operator!=(const Bignum &other) {
        bnword_t flag = 0;
        for (size_t i = 0; i < wordlen; i++) {
            flag |= cwords()[i] ^ other.cwords()[i];
        }
        return flag;
    }

    /**
     * Adds this number to the argument, and returns their sum.  The size of
     * the sum is the size of the largest of the arguments.  In addition,
     * allows a carry-in and carry-out bit.
     */
    std::unique_ptr<Bignum> add_to(const Bignum &other, bool carryin,
                                   bool &carryout);

    /**
     * Adds this number to the argument, and returns their sum.  The size of
     * the sum is the size of the largest of the arguments.
     */
    inline std::unique_ptr<Bignum> add_to(const Bignum &other) {
        bool discard;
        return add_to(other, false, discard);
    }

    /**
     * Adds the specified number to this one.  Note that this does not
     * autopromote the number.
     */
    void increase_by(const Bignum &other, bool carryin, bool &carryout);

    /**
     * Adds the specified number to this one.  Note that this does not
     * autopromote the number.
     */
    inline void increase_by(const Bignum &other) {
        bool discard;
        increase_by(other, false, discard);
    }

    /**
     * Decreases the number by specified number.
     */
    void decrease_by(const Bignum &other);

    /**
     * Multiply this number by another, and return the result.  The size of the
     * number is 2 * max(|this|, |other|).
     */
    std::unique_ptr<Bignum> multiply_by(const Bignum &other);
};

typedef std::unique_ptr<Bignum> Bignum_u;

}

#endif /* __CRYPTO_BIGNUM_HH */
