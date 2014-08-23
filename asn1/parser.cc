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

    // Prevent stack overflows
    assert_format(options.recursion_depth <= recursion_depth_limit);

    // Do not support multibyte tag values, since no known crypto app we
    // currently want to support uses that
    assert_format(tag != 0x1f);

    uint8_t init_len = read_uint8();
    assert_format(init_len != 0xff);

    if (init_len == 0x80) {
        // Handle indefinite length.  This code to some extent duplicates the
        // code below for constructed types, but it has to construct things in
        // a somewhat different fashion, and also most of the complicated code
        // for definite-length case handles BER constraints (which we don't
        // have to).

        // Check if indefinite length is even allowed here
        assert_format(!is_der);
        assert_format(constructed);

        // Check if the tag in question can be constructed in BER
        if (data_class == Universal) {
            UniversalType univ_tag = static_cast<UniversalType>(tag);
            assert_format(can_be_constructed_type(univ_tag));
        }

        // Construct a blob which contains the remainder of the data to parse
        size_t remaining_length = source.size() - offset;
        const memslice domain = crypto::cmem(source.cptr() + offset, remaining_length);

        // Set up the nested parser
        Parser_u nested_parser(new Parser(domain, options.deeper()));

        // Read data until we find an EOC
        std::unique_ptr<std::vector<Data_u>> elems(new std::vector<Data_u>());
        for (;;) {
            Data_u nested_element = nested_parser->parse();
            assert_format(nested_element != nullptr);

            if (nested_element->is_universal_type(UTEndOfContent)) {
                break;
            } else {
                elems->emplace_back(nested_element.release());
            }
        }

        // Adjust the offset of the outer parser
        size_t len = nested_parser->get_current_offset();
        assert_has_bytes(len);  // sanity check
        offset += len;

        const memslice body = crypto::cmem(domain.cptr(), len);

        return Data_u(new ConstructedData(tag, constructed, data_class,
                    body, std::move(elems)));
    } else {
        size_t len = 0;
        if (init_len & 0x80) {
            // Long form
            size_t len_len = init_len & 0x7f;

            // Discard all lengths the platform cannot even represent
            assert_format(len_len < sizeof(size_t));

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

            // Set up the nested parser
            Parser_u nested_parser(new Parser(body, options.deeper()));

            // Read all nested values
            std::unique_ptr<std::vector<Data_u>> elems(new std::vector<Data_u>());
            while (nested_parser->has_unconsumed_data()) {
                Data_u nested_element = nested_parser->parse();
                assert_format(nested_element != nullptr);

                // Enforce DER ordering constraint on sets here
                if (enforce_set_order && elems->size() > 0) {
                    const memslice prev_body = (*elems)[elems->size() - 1]->get_body();
                    assert_format(nested_element->get_body().cmp(prev_body) >= 0);
                }
                elems->emplace_back(nested_element.release());
            }

            return Data_u(new ConstructedData(tag, constructed, data_class,
                        body, std::move(elems)));
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
                    return Data_u(new BooleanData(tag, constructed, data_class, body));
                }

                // Parse OIDs
                if (univ_tag == UTOID) {
                    OIDData_u oid(new OIDData(tag, constructed, data_class, body));
                    assert_format(oid->validate());
                    return Data_u(oid.release());
                }

                // Parse UTCTime
                if (univ_tag == UTUTCTime) {
                    UTCTimeData_u time(new UTCTimeData(tag, constructed, data_class, body, options));
                    assert_format(time->validate());
                    return Data_u(time.release());
                }

                // Handle text types
                if (is_text_type(univ_tag)) {
                    TextData_u text(new TextData(tag, constructed, data_class, body, options));
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

}
