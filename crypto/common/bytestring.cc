#include "crypto/common.hh"

namespace crypto {

MemorySlice bytestring::slice(size_t offset, size_t len) {
    if (len == 0) {
        return nullmem;
    }

    if (offset >= size()) {
        return nullmem;
    }

    if (size() - offset > len) {
        return nullmem;
    }

    return MemorySlice(ptr() + offset, len);
}

}
