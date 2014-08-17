#ifndef __CRYPTO_PARSER_HH
#define __CRYPTO_PARSER_HH

#include "crypto/common.hh"

#include <byteswap.h>

namespace crypto {

enum ParserFailureMode {
    InvalidFormat,
    OutOfBounds,
    UnconsumedData
};

// FIXME: the code below assumes the platform is little-endian

/**
 * A base class for parsers which parse binary data formats.  The template
 * accepts two arguments: the type that parser outputs and the endianness of
 * the input data.
 *
 * The parsing logic is specified by redefining the parse_core method.  The
 * parsing logic should be using the read_* methods which will automatically
 * check bounds, and assert_format() and format_fail() in order to return error
 * automatically.  The parsing logic should be aware that those assertions are
 * implemented using exceptions and use RAII.
 */
template<typename T, Endianness endianness>
class BaseParser {
  protected:
    typedef std::unique_ptr<T> T_u;

    bool valid = true;
    ParserFailureMode failure;
    const memslice source;
    size_t offset = 0;

    /**
     * Method which defines the parsing logic.
     */
    virtual T_u parse_core() = 0;

  public:
    BaseParser(const memslice source_) : source(source_) {};
    virtual ~BaseParser() {};

    inline bool has_unconsumed_data() { return offset < source.size(); }
    inline size_t get_current_offset() { return offset; }
    inline bool is_valid() { return valid; }
    inline ParserFailureMode get_failure_mode() { return failure; }

    /**
     * External interface for parsing.  Calling parse() will advance the
     * internal pointer.  Returns nullptr if an error occurred.
     */
    T_u parse() noexcept {
        if (!valid) {
            return nullptr;
        }

        T_u output;
        try {
            return parse_core();
        } catch (ParserFailureMode mode) {
            valid = false;
            failure = mode;
            return nullptr;
        }
    }

    /**
     * External interface for parsing.  Will only succeed when all the data is
     * consumed.
     */
    T_u parse_all() {
        T_u output = parse();

        if (output && has_unconsumed_data()) {
            failure = UnconsumedData;
            return nullptr;
        }

        return output;
    }

  protected:
    /**
     * Throw a failure if there are less than |bytes| bytes remaining.
     */
    void assert_has_bytes(size_t bytes) {
        if (bytes == 0) {
            return;
        }

        if (offset >= source.size()) {
            throw OutOfBounds;
        }

        if (source.size() - offset < bytes) {
            throw OutOfBounds;
        }
    }

    /**
     * Check if there are |bytes| bytes, and if so, return the pointer to the
     * current position and advance it by |bytes|.
     */
    const uint8_t *read_bytes(size_t bytes) {
        const uint8_t *result = source.cptr() + offset;
        assert_has_bytes(bytes);
        offset += bytes;
        return result;
    }

    /**
     * Indicate parser failure due to format being incorrect.
     */
    void format_fail() {
        throw InvalidFormat;
    }

    /**
     * Fail if assertion is false.
     */
    void assert_format(bool assertion) {
        if (!assertion) {
            format_fail();
        }
    }

    /**
     * Read a byte.
     */
    const uint8_t read_uint8() {
        return *read_bytes(1);
    }

    /**
     * Read an unsigned 16-bit value.
     */
    const uint16_t read_uint16() {
        if (endianness == BigEndian) {
            return __bswap_16(
                    *reinterpret_cast<const uint16_t*>(read_bytes(2)));
        } else {
            return *reinterpret_cast<const uint16_t*>(read_bytes(2));
        }
    }

    /**
     * Read an unsigned 32-bit value.
     */
    const uint32_t read_uint32() {
        if (endianness == BigEndian) {
            return __bswap_32(
                    *reinterpret_cast<const uint32_t*>(read_bytes(4)));
        } else {
            return *reinterpret_cast<const uint32_t*>(read_bytes(4));
        }
    }

    /**
     * Read an unsigned 64-bit value.
     */
    const uint64_t read_uint64() {
        if (endianness == BigEndian) {
            return __bswap_64(
                    *reinterpret_cast<const uint64_t*>(read_bytes(8)));
        } else {
            return *reinterpret_cast<const uint64_t*>(read_bytes(8));
        }
    }

    /**
     * Read an unsigned 24-bit value.  This is required to parse some lengths
     * in TLS.
     */
    const uint32_t read_uint24() {
        const uint8_t *ptr = read_bytes(3);
        if (endianness == BigEndian) {
            return ptr[2] | (ptr[1] << 8) | (ptr[0] << 16);
        } else {
            return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16);
        }
    }

    /**
     * Read a memory slice of specified size.
     */
    const memslice read_blob(size_t len) {
        return cmem(read_bytes(len), len);
    }

    /**
     * Read a memory slice prefixed with 8-bit length.
     */
    const memslice read_uint8_length_prefixed() {
        size_t len = read_uint8();
        return read_blob(len);
    }

    /**
     * Read a memory slice prefixed with 8-bit length.  Fails if the length is
     * above minimum or below maximum.
     */
    const memslice read_uint8_length_prefixed(uint8_t minlen, uint8_t maxlen) {
        size_t len = read_uint8();
        assert_format(len >= minlen && len <= maxlen);
        return read_blob(len);
    }

    /**
     * Read a memory slice prefixed with 16-bit length.
     */
    const memslice read_uint16_length_prefixed() {
        size_t len = read_uint16();
        return read_blob(len);
    }

    /**
     * Read a memory slice prefixed with 16-bit length.  Fails if the length is
     * above minimum or below maximum.
     */
    const memslice read_uint16_length_prefixed(uint16_t minlen, uint16_t maxlen) {
        size_t len = read_uint16();
        assert_format(len >= minlen && len <= maxlen);
        return read_blob(len);
    }

    /**
     * Read a memory slice prefixed with 24-bit length.
     */
    const memslice read_uint24_length_prefixed() {
        size_t len = read_uint24();
        return read_blob(len);
    }

    /**
     * Read a memory slice prefixed with 24-bit length.  Fails if the length is
     * above minimum or below maximum.
     */
    const memslice read_uint24_length_prefixed(uint32_t minlen, uint32_t maxlen) {
        size_t len = read_uint24();
        assert_format(len >= minlen && len <= maxlen);
        return read_blob(len);
    }
};

}

#endif  /* __CRYPTO_PARSER_HH */
