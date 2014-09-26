#ifndef __CRYPTO_BIGNUM_HH
#define __CRYPTO_BIGNUM_HH

#include "crypto/common.hh"

#include <algorithm>
#include <cstring>

namespace crypto {

constexpr static bool is_power_of_two(size_t n) {
    return n == 2 || (!(n & 1) ? is_power_of_two(n / 2) : false);
}

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

/**
 * Base class for big numbers.  Implements functions which do not need to be
 * inline-expanded.
 */
class AnyBignum {
  protected:
    bytestring data;

    AnyBignum(size_t NB) : data(NB) {}
  public:
    virtual size_t len_bytes() = 0;
    inline size_t len_words() { return len_bytes() / sizeof(uint64_t); }
};

/**
 * Represents N-bit numbers in little endian format.
 */
template<size_t N>
class Bignum : public AnyBignum {
  public:
      constexpr static size_t NB = N / 8;
      constexpr static size_t NW = NB / sizeof(uint64_t);

      Bignum() : AnyBignum(NB) {
          static_assert(N > 0, "Bignums have to be at least 64-bit");
          static_assert(is_power_of_two(N), "Bignums have to be a power of two");
      }

      Bignum(uint8_t init) : Bignum() {
          data[0] = init;
      }

      Bignum(uint64_t *words) : Bignum() {
          std::copy(words, words + NW, data64());
      }

      virtual size_t len_bytes() override { return NB; }

      inline bytestring &get_data() { return data; }
      inline const bytestring &get_data() const { return data; }
      inline uint32_t *data32() { return reinterpret_cast<uint32_t*>(data.ptr()); }
      inline uint64_t *data64() { return reinterpret_cast<uint64_t*>(data.ptr()); }
      inline const uint32_t *cdata32() const { return reinterpret_cast<const uint32_t*>(data.cptr()); }
      inline const uint64_t *cdata64() const { return reinterpret_cast<const uint64_t*>(data.cptr()); }

      /**
       * In-place binary inversion of the bignum.
       */
      void bin_inverse() {
          for (size_t i = 0; i < NW; i++) {
              data64()[i] = ~data64()[i];
          }
      }

      /**
       * Test if all digits are zeroes.
       */
      inline explicit operator bool() const {
          bool result = false;
          for (size_t i = 0; i < NW; i++) {
              result |= cdata64()[i];
          }
          return result;
      }

      /**
       * Convert to full hexadecimal representation (including leading zeroes).
       */
      std::string to_hex() const {
          std::string result;
          result.resize(NB * 2);
          for (size_t i = 0; i < NB; i++) {
              result[2*i]   = digit_to_hex(data[NB-i-1] >> 4);
              result[2*i+1] = digit_to_hex(data[NB-i-1] & 0x0f);
          }
          return result;
      }

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
      bool from_hex(const memslice src) {
          if (src.size() != NB * 2) {
              return false;
          }

          if (!std::all_of(src.ccharptr(), src.ccharptr() + src.size(), is_hex_char)) {
              return false;
          }


          bytestring orig = bytestring::from_hex(src);
          std::copy(orig.crbegin(), orig.crend(), data.begin());

          return true;
      }

      /**
       * Constant-type inequality test.
       */
      inline bool operator!=(const Bignum<N> &other) {
          uint64_t flag = 0;
          for (size_t i = 0; i < NW; i++) {
              flag |= cdata64()[i] ^ other.cdata64()[i];
          }
          return flag;
      }
};

}

#include "crypto/bignum/impl.hh"

#endif /* __CRYPTO_BIGNUM_HH */
