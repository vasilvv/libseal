#include "crypto/common.hh"

#include <cstdlib>

namespace crypto {

bytestring::bytestring(const char *str) {
    size_t src_len = strlen(str);
    resize(src_len);
    memcpy(ptr(), str, src_len);
}

memslice bytestring::slice(size_t offset, size_t len) {
    if (len == 0) {
        return nullmem;
    }

    if (offset >= size()) {
        return nullmem;
    }

    if (size() - offset > len) {
        return nullmem;
    }

    return memslice(ptr() + offset, len);
}

bytestring bytestring::from_hex(const memslice hex) {
    // FIXME: assert mod-2
    size_t output_len = hex.size() / 2;

    bytestring result(output_len);
    char buffer[3] = { 0, 0, 0 };
    for (size_t i = 0; i < output_len; i++) {
        buffer[0] = hex.ccharptr()[2 * i];
        buffer[1] = hex.ccharptr()[2 * i + 1];
        result[i] = static_cast<uint8_t>(strtoul(buffer, nullptr, 16));
    }

    return result;
}

}
