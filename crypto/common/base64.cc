#include "crypto/common.hh"

#include "modp_b64.h"

namespace crypto {

bytestring_u base64_encode(const memslice input) {
    size_t output_max_len = modp_b64_encode_len(input.size());
    bytestring_u output(new bytestring(output_max_len));

    size_t actual_size =
        modp_b64_encode(output->charptr(), input.ccharptr(), input.size());
    output->resize(actual_size);
    return output;
}

bytestring_u base64_decode(const memslice input) {
    size_t output_max_len = modp_b64_decode_len(input.size());
    bytestring_u output(new bytestring(output_max_len));

    size_t actual_size =
        modp_b64_decode(output->charptr(), input.ccharptr(), input.size());
    if (actual_size == MODP_B64_ERROR) {
        return nullptr;
    }

    output->resize(actual_size);
    return output;
}

}
