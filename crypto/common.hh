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
 * if you have a const MemorySlice.  To create a const MemorySlice, use cmem()
 * function.
 *
 * By convention, a null memory slice is represented as {nullptr, 0},
 * which is normally referred to as nullmem.
 */
struct MemorySlice {
  private:
    uint8_t *ptr_;
    size_t size_;

  public:
    inline MemorySlice(uint8_t *ptr, size_t size)
        : ptr_(ptr), size_(size) {}
    operator bool() { return ptr_ != nullptr; }

    uint8_t *ptr() { return ptr_; }
    const uint8_t *cptr() const { return ptr_; }
    const size_t size() const { return size_; }
};

const MemorySlice nullmem = { nullptr, 0 };

// Convenience functions
inline MemorySlice mem(uint8_t *ptr, size_t size) {
    return MemorySlice(ptr, size);
}

inline const MemorySlice cmem(const uint8_t *ptr, size_t size) {
    return MemorySlice(const_cast<uint8_t*>(ptr), size);
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
     * Returns the pointer and the length of the buffer.
     */
    inline MemorySlice mem() { return MemorySlice(ptr(), size()); }

    /**
     * Return the constant pointer and the length of the buffer.
     */
    inline const MemorySlice cmem() const {
        return crypto::cmem(cptr(), size());
    }

    /**
     * Return a pointer to a subset of the string; returns nullmem if goes out
     * of bounds or if specified length is zero.
     */
    MemorySlice slice(size_t offset, size_t len);

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
     * Create buffer by copying another buffer (MemorySlice).
     */
    bytestring(const MemorySlice mem)
        : std::basic_string<uint8_t>(mem.cptr(), mem.size()) {}

    /**
     * Create a buffer from an initializer list of bytes.
     */
    bytestring(std::initializer_list<uint8_t> il)
        : std::basic_string<uint8_t>(il) {};

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
    void copy_from(const MemorySlice mem) {
        resize(mem.size());
        memcpy(ptr(), mem.cptr(), mem.size());
    }

    /**
     * Convert a well-formed hexadecimal string into corresponding bytestring.
     */
    static bytestring from_hex(const char *hex);
};
typedef std::unique_ptr<bytestring> bytestring_u;

}

#endif /* __CRYPTO_COMMON_HH */
