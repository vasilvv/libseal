#ifndef __CRYPTO_COMMON_HH
#define __CRYPTO_COMMON_HH

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

namespace crypto {

/**
 * A generic structure to represent a pointer to a bounded segment in the
 * memory without any assertions on the ownership of that segment.
 *
 * The class has two accessors: ptr() and cptr().  First returns a read-write
 * pointer, second returns read-only pointer, and it's the only one you can use
 * if you have a const memslice.  To create a const memslice, use cmem()
 * function.
 *
 * By convention, a null memory slice is represented as {nullptr, 0},
 * which is normally referred to as nullmem.
 */
struct memslice {
  private:
    uint8_t *ptr_;
    size_t size_;

  public:
    inline memslice(uint8_t *ptr, size_t size)
        : ptr_(ptr), size_(size) {}
    inline explicit operator bool() { return ptr_ != nullptr; }

    inline uint8_t *ptr() { return ptr_; }
    inline char *charptr() { return reinterpret_cast<char*>(ptr_); }
    inline const uint8_t *cptr() const { return ptr_; }
    inline const char *ccharptr() const { return reinterpret_cast<const char*>(ptr_); }
    inline const size_t size() const { return size_; }

    inline bool eq(const memslice other) const {
        return !(size() != other.size() || memcmp(cptr(), other.cptr(), size()));
    }
    inline int cmp(const memslice other) const {
        int cmp_shortest = memcmp(cptr(), other.cptr(), std::min(size(), other.size()));
        if (cmp_shortest == 0 && size() != other.size()) {
            return size() > other.size() ? 1 : -1;
        } else {
            return cmp_shortest;
        }
    }
};

const memslice nullmem = { nullptr, 0 };

// Convenience functions
inline memslice mem(uint8_t *ptr, size_t size) {
    return memslice(ptr, size);
}

inline const memslice cmem(const uint8_t *ptr, size_t size) {
    return memslice(const_cast<uint8_t*>(ptr), size);
}

/**
 * A generic class representing a buffer containing bytes.
 */
class bytestring : public std::basic_string<uint8_t> {
  public:
    /**
     * Returns a pointer to the contents of the buffer.
     */
    inline uint8_t *ptr() { return empty() ? nullptr : &*begin(); }

    /**
     * Returns a constant pointer to the contents of the buffer.
     */
    inline const uint8_t *cptr() const {
        return empty() ? nullptr : &*cbegin();
    }

    /**
     * Wrapper for functions which accept char* pointers.
     */
    inline char *charptr() {
        return reinterpret_cast<char*>(ptr());
    }

    /**
     * Wrapper for functions which accept const char* pointers.
     */
    inline const char *ccharptr() const {
        return reinterpret_cast<const char*>(cptr());
    }

    /**
     * Returns the pointer and the length of the buffer.
     */
    inline memslice mem() { return memslice(ptr(), size()); }

    /**
     * Return the constant pointer and the length of the buffer.
     */
    inline const memslice cmem() const {
        return crypto::cmem(cptr(), size());
    }

    /**
     * Return a pointer to a subset of the string; returns nullmem if goes out
     * of bounds or if specified length is zero.
     */
    memslice slice(size_t offset, size_t len);

    /**
     * Create empty buffer.
     */
    bytestring() : std::basic_string<uint8_t>() {}

    /**
     * Create buffer by copying another buffer (C-style).
     */
    bytestring(const uint8_t *data, size_t size)
        : std::basic_string<uint8_t>(data, size) {}

    /**
     * Create buffer by copying another buffer (memslice).
     */
    bytestring(const memslice mem)
        : std::basic_string<uint8_t>(mem.cptr(), mem.size()) {}

    /**
     * Create a buffer from an initializer list of bytes.
     */
    bytestring(std::initializer_list<uint8_t> il)
        : std::basic_string<uint8_t>(il) {};

    /**
     * Create a bytestring from a C string.
     */
    bytestring(const char *str);

    /**
     * Constructor to upgrade basic_string<uint8_t> to bytestring.
     */
    bytestring(const std::basic_string<uint8_t> &val)
        : bytestring(::crypto::cmem(val.data(), val.size())) {}

    /**
     * Create a buffer of a specific size.
     */
    bytestring(size_t len) : std::basic_string<uint8_t>() {
        resize(len);
    }

    /**
     * Replace the contents of the buffer with the contents of the pointed
     * memory.
     */
    void copy_from(const memslice mem) {
        resize(mem.size());
        memcpy(ptr(), mem.cptr(), mem.size());
    }

    /**
     * Convert a well-formed hexadecimal string into corresponding bytestring.
     */
    static bytestring from_hex(const char *hex);

    /**
     * Convert the contents of this object to std::string.
     */
    inline std::string to_string() const {
        return std::string(ccharptr(), size());
    }
};
typedef std::unique_ptr<bytestring> bytestring_u;

/**
 * Basic base64 encoding functions.  Do not handle any whitespace.  In case if
 * whitespace or any other non-format data is present, base64_decode returns
 * nullptr.
 */
bytestring_u base64_encode(const memslice input);
bytestring_u base64_decode(const memslice input);

enum Endianness {
    BigEndian,
    LittleEndian
};

}

#endif /* __CRYPTO_COMMON_HH */
