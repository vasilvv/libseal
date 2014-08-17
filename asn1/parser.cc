#include "asn1/parser.hh"

namespace asn1 {

/**
 * Returns number of bytes necessary to actually represent the number.
 */
static uint8_t log256(size_t num) {
    uint8_t result = 0;
    while (num) {
        num = num >> 8;
        result++;
    }
    return result;
}

/**
 * Core logic of BER/DER parser.
 *
 * Attention: since all asserts and reads here can throw exceptions, do not use
 * anything that does not rely on RAII.
 */
Data_u Parser::parse_core() {
    uint8_t full_tag = read_uint8();
    uint8_t tag = full_tag & 0x1f;
    bool constructed = (full_tag & 0x20) >> 5;
    Class data_class = static_cast<Class>((full_tag & 0xc0) >> 6);

    // Do not support multibyte tag values, since no known crypto app we
    // currently want to support uses that
    assert_format(tag != 0x1f);

    uint8_t init_len = read_uint8();
    size_t len = 0;
    assert_format(init_len != 0xff);
    if (init_len & 0x80) {
        // Long form
        size_t len_len = init_len & 0x7f;

        // Discard all lengths the platform cannot even represent
        assert_format(len_len < sizeof(size_t));
        // Do not support indefinite length
        assert_format(len_len != 0);

        for (size_t i = len_len; i > 0; i--) {
            len = (len << 8) | read_uint8();
        }

        // Enforce shortest length constraint
        if (is_der) {
            assert_format(len >= 128);   // Should have used short format
            assert_format(log256(len) == len_len);
        }
    } else {
        // Short form
        len = init_len;
    }

    const memslice body = read_blob(len);
    if (constructed) {
        // For all constructed types, parse the nested values
        bool enforce_set_order = false;

        // Filter out some primitive universal types
        if (data_class == Universal) {
            UniversalType univ_tag = static_cast<UniversalType>(tag);
            assert_format(is_constructed_type(univ_tag) ||
                    (!is_der && can_be_constructed_type(univ_tag)));

            // Determine in advance whether we need to enforce elements in sets to
            // come in order.  This is a DER constraint.
            if (univ_tag == UTSet && is_der) {
                enforce_set_order = true;
            }
        }

        ConstructedData_u container(new ConstructedData(tag, constructed, data_class, body));

        // Pick the necessary parser for the nested value
        Parser_u nested_parser(new Parser(body, options));

        // Read all nested values
        std::vector<Data_u> &elems = container->elements;
        while (nested_parser->has_unconsumed_data()) {
            Data_u nested_element = nested_parser->parse();
            assert_format(nested_element != nullptr);

            // Enforce DER ordering constraint on sets here
            if (enforce_set_order && elems.size() > 1) {
                const memslice prev_body = elems[elems.size() - 1]->get_body();
                assert_format(nested_element->get_body().cmp(prev_body) >= 0);
            }
            elems.emplace_back(nested_element.release());
        }

        return Data_u(container.release());
    } else {
        if (data_class == Universal) {
            UniversalType univ_tag = static_cast<UniversalType>(tag);
            assert_format(!is_constructed_type(univ_tag));

            // Parse booleans
            if (univ_tag == UTBoolean) {
                assert_format(len == 1);
                if (is_der) {
                    uint8_t val = *body.cptr();
                    assert_format(val == 0xff || val == 0x00);
                }
                return Data_u(new Boolean(tag, constructed, data_class, body));
            }

            // Handle text types
            if (is_text_type(univ_tag)) {
                Text_u text(new Text(tag, constructed, data_class, body, options));
                assert_format(text->validate());
                return Data_u(text.release());
            }

            // Enforce constrains on nulls
            if (univ_tag == UTNull) {
                assert_format(len == 0);
            }
        }

        // All data for which we do not provide special handling is returned
        // as is
        Data_u data(new Data(tag, constructed, data_class, body));
        return data;
    }
}

}
