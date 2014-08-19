#include "asn1/oid.hh"

#include "crypto/parser.hh"

#include <sstream>

namespace asn1 {

OID::OID(const std::initializer_list<OIDComponent> components) {
    std::initializer_list<OIDComponent>::iterator iter = components.begin();

    uint8_t first_byte = 40 * *(iter++);
    first_byte += *(iter++);
    der.push_back(first_byte);

    for (; iter != components.end(); iter++) {
        OIDComponent value = *iter;

        // Construct the encoding in little-endian first
        bytestring value_le;
        do {
            value_le.push_back((value & 0x7f) | 0x80);
            value >>= 7;
        } while(value);
        value_le[0] &= 0x7f;

        // Then append in big-endian
        der.append(value_le.rbegin(), value_le.rend());
    }
}

OIDComponents_u OID::get_components() const {
    if (der.size() < 1) {
        return nullptr;
    }

    OIDComponents_u result(new OIDComponents());

    // First byte = OID[0] * 40 + OID[1]
    uint8_t first_component = der[0] / 40;
    result->push_back(first_component);
    result->push_back(der[0] - first_component * 40);

    // Iterate over the rest in a loop
    bool pending = false;
    OIDComponent current = 0;
    size_t current_len = 0;
    for (bytestring::const_iterator iter = der.cbegin() + 1; iter != der.cend(); iter++) {
        // Fail if the OID is too long to be represented
        current_len++;
        if (current_len * 7 > sizeof(OIDComponent) * 8) {
            return nullptr;
        }

        current |= *iter & 0x7f;

        pending = *iter & 0x80;
        if (pending) {
            current <<= 7;
        } else {
            result->push_back(current);

            // Reset the parser
            current = 0;
            current_len = 0;
        }
    }
    // Fail if OID is not finished
    if (pending) {
        return nullptr;
    }

    return result;
}

std::string OID::to_string() const {
    OIDComponents_u components = get_components();
    if (components) {
        std::string result;
        for (auto &component : *components) {
            result.append(std::to_string(component));
            result.push_back('.');
        }

        result.resize(result.size() - 1);
        return result;
    } else {
        return "[invalid OID]";
    }
}

}
