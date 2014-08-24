#include "asn1/data.hh"

#include <ctype.h>
#include <iconv.h>

#include <algorithm>

namespace asn1 {

/* T.61 --> UTF-8 conversion table */
static const char *T61Table[256] = {
    /* 0x00 */ "\x00", /* 0x01 */ "\x01", /* 0x02 */ "\x02", /* 0x03 */ "\x03",
    /* 0x04 */ "\x04", /* 0x05 */ "\x05", /* 0x06 */ "\x06", /* 0x07 */ "\x07",
    /* 0x08 */ "\x08", /* 0x09 */ "\x09", /* 0x0a */ "\x0a", /* 0x0b */ "\x0b",
    /* 0x0c */ "\x0c", /* 0x0d */ "\x0d", /* 0x0e */ "\x0e", /* 0x0f */ "\x0f",
    /* 0x10 */ "\x10", /* 0x11 */ "\x11", /* 0x12 */ "\x12", /* 0x13 */ "\x13",
    /* 0x14 */ "\x14", /* 0x15 */ "\x15", /* 0x16 */ "\x16", /* 0x17 */ "\x17",
    /* 0x18 */ "\x18", /* 0x19 */ "\x19", /* 0x1a */ "\x1a", /* 0x1b */ "\x1b",
    /* 0x1c */ "\x1c", /* 0x1d */ "\x1d", /* 0x1e */ "\x1e", /* 0x1f */ "\x1f",
    /* 0x20 */ "\x20", /* 0x21 */ "\x21", /* 0x22 */ "\x22", /* 0x23 */ "",
    /* 0x24 */ "",     /* 0x25 */ "\x25", /* 0x26 */ "\x26", /* 0x27 */ "\x27",
    /* 0x28 */ "\x28", /* 0x29 */ "\x29", /* 0x2a */ "\x2a", /* 0x2b */ "\x2b",
    /* 0x2c */ "\x2c", /* 0x2d */ "\x2d", /* 0x2e */ "\x2e", /* 0x2f */ "\x2f",
    /* 0x30 */ "\x30", /* 0x31 */ "\x31", /* 0x32 */ "\x32", /* 0x33 */ "\x33",
    /* 0x34 */ "\x34", /* 0x35 */ "\x35", /* 0x36 */ "\x36", /* 0x37 */ "\x37",
    /* 0x38 */ "\x38", /* 0x39 */ "\x39", /* 0x3a */ "\x3a", /* 0x3b */ "\x3b",
    /* 0x3c */ "\x3c", /* 0x3d */ "\x3d", /* 0x3e */ "\x3e", /* 0x3f */ "\x3f",
    /* 0x40 */ "\x40", /* 0x41 */ "\x41", /* 0x42 */ "\x42", /* 0x43 */ "\x43",
    /* 0x44 */ "\x44", /* 0x45 */ "\x45", /* 0x46 */ "\x46", /* 0x47 */ "\x47",
    /* 0x48 */ "\x48", /* 0x49 */ "\x49", /* 0x4a */ "\x4a", /* 0x4b */ "\x4b",
    /* 0x4c */ "\x4c", /* 0x4d */ "\x4d", /* 0x4e */ "\x4e", /* 0x4f */ "\x4f",
    /* 0x50 */ "\x50", /* 0x51 */ "\x51", /* 0x52 */ "\x52", /* 0x53 */ "\x53",
    /* 0x54 */ "\x54", /* 0x55 */ "\x55", /* 0x56 */ "\x56", /* 0x57 */ "\x57",
    /* 0x58 */ "\x58", /* 0x59 */ "\x59", /* 0x5a */ "\x5a", /* 0x5b */ "\x5b",
    /* 0x5c */ "",     /* 0x5d */ "\x5d", /* 0x5e */ "",     /* 0x5f */ "\x5f",
    /* 0x60 */ "",     /* 0x61 */ "\x61", /* 0x62 */ "\x62", /* 0x63 */ "\x63",
    /* 0x64 */ "\x64", /* 0x65 */ "\x65", /* 0x66 */ "\x66", /* 0x67 */ "\x67",
    /* 0x68 */ "\x68", /* 0x69 */ "\x69", /* 0x6a */ "\x6a", /* 0x6b */ "\x6b",
    /* 0x6c */ "\x6c", /* 0x6d */ "\x6d", /* 0x6e */ "\x6e", /* 0x6f */ "\x6f",
    /* 0x70 */ "\x70", /* 0x71 */ "\x71", /* 0x72 */ "\x72", /* 0x73 */ "\x73",
    /* 0x74 */ "\x74", /* 0x75 */ "\x75", /* 0x76 */ "\x76", /* 0x77 */ "\x77",
    /* 0x78 */ "\x78", /* 0x79 */ "\x79", /* 0x7a */ "\x7a", /* 0x7b */ "",
    /* 0x7c */ "\x7c", /* 0x7d */ "",     /* 0x7e */ "",     /* 0x7f */ "\x7f",
    /* 0x80 */ "\xc2\x80", /* 0x81 */ "\xc2\x81", /* 0x82 */ "\xc2\x82",
    /* 0x83 */ "\xc2\x83", /* 0x84 */ "\xc2\x84", /* 0x85 */ "\xc2\x85",
    /* 0x86 */ "\xc2\x86", /* 0x87 */ "\xc2\x87", /* 0x88 */ "\xc2\x88",
    /* 0x89 */ "\xc2\x89", /* 0x8a */ "\xc2\x8a", /* 0x8b */ "\xc2\x8b",
    /* 0x8c */ "\xc2\x8c", /* 0x8d */ "\xc2\x8d", /* 0x8e */ "\xc2\x8e",
    /* 0x8f */ "\xc2\x8f", /* 0x90 */ "\xc2\x90", /* 0x91 */ "\xc2\x91",
    /* 0x92 */ "\xc2\x92", /* 0x93 */ "\xc2\x93", /* 0x94 */ "\xc2\x94",
    /* 0x95 */ "\xc2\x95", /* 0x96 */ "\xc2\x96", /* 0x97 */ "\xc2\x97",
    /* 0x98 */ "\xc2\x98", /* 0x99 */ "\xc2\x99", /* 0x9a */ "\xc2\x9a",
    /* 0x9b */ "\xc2\x9b", /* 0x9c */ "\xc2\x9c", /* 0x9d */ "\xc2\x9d",
    /* 0x9e */ "\xc2\x9e", /* 0x9f */ "\xc2\x9f", /* 0xa0 */ "",
    /* 0xa1 */ "\xc2\xa1", /* 0xa2 */ "\xc2\xa2", /* 0xa3 */ "\xc2\xa3",
    /* 0xa4 */ "\x24",     /* 0xa5 */ "\xc2\xa5", /* 0xa6 */ "\x23",
    /* 0xa7 */ "\xc2\xa7", /* 0xa8 */ "\xc2\xa4", /* 0xa9 */ "", /* 0xaa */ "",
    /* 0xab */ "\xc2\xab", /* 0xac */ "", /* 0xad */ "", /* 0xae */ "",
    /* 0xaf */ "",         /* 0xb0 */ "\xc2\xb0", /* 0xb1 */ "\xc2\xb1",
    /* 0xb2 */ "\xc2\xb2", /* 0xb3 */ "\xc2\xb3", /* 0xb4 */ "\xc3\x97",
    /* 0xb5 */ "\xc2\xb5", /* 0xb6 */ "\xc2\xb6", /* 0xb7 */ "\xc2\xb7",
    /* 0xb8 */ "\xc3\xb7", /* 0xb9 */ "", /* 0xba */ "", /* 0xbb */ "\xc2\xbb",
    /* 0xbc */ "\xc2\xbc", /* 0xbd */ "\xc2\xbd", /* 0xbe */ "\xc2\xbe",
    /* 0xbf */ "\xc2\xbf", /* 0xc0 */ "", /* 0xc1 */ "", /* 0xc2 */ "",
    /* 0xc3 */ "", /* 0xc4 */ "", /* 0xc5 */ "", /* 0xc6 */ "", /* 0xc7 */ "",
    /* 0xc8 */ "", /* 0xc9 */ "", /* 0xca */ "", /* 0xcb */ "", /* 0xcc */ "",
    /* 0xcd */ "", /* 0xce */ "", /* 0xcf */ "", /* 0xd0 */ "", /* 0xd1 */ "",
    /* 0xd2 */ "", /* 0xd3 */ "", /* 0xd4 */ "", /* 0xd5 */ "", /* 0xd6 */ "",
    /* 0xd7 */ "", /* 0xd8 */ "", /* 0xd9 */ "", /* 0xda */ "", /* 0xdb */ "",
    /* 0xdc */ "", /* 0xdd */ "", /* 0xde */ "", /* 0xdf */ "",
    /* 0xe0 */ "\xe2\x84\xa6", /* 0xe1 */ "\xc3\x86", /* 0xe2 */ "\xc3\x90",
    /* 0xe3 */ "\xc2\xaa", /* 0xe4 */ "\xc4\xa6", /* 0xe5 */ "",
    /* 0xe6 */ "\xc4\xb2", /* 0xe7 */ "\xc4\xbf", /* 0xe8 */ "\xc5\x81",
    /* 0xe9 */ "\xc3\x98", /* 0xea */ "\xc5\x92", /* 0xeb */ "\xc2\xba",
    /* 0xec */ "\xc3\x9e", /* 0xed */ "\xc5\xa6", /* 0xee */ "\xc5\x8a",
    /* 0xef */ "\xc5\x89", /* 0xf0 */ "\xc4\xb8", /* 0xf1 */ "\xc3\xa6",
    /* 0xf2 */ "\xc4\x91", /* 0xf3 */ "\xc3\xb0", /* 0xf4 */ "\xc4\xa7",
    /* 0xf5 */ "\xc4\xb1", /* 0xf6 */ "\xc4\xb3", /* 0xf7 */ "\xc5\x80",
    /* 0xf8 */ "\xc5\x82", /* 0xf9 */ "\xc3\xb8", /* 0xfa */ "\xc5\x93",
    /* 0xfb */ "\xc3\x9f", /* 0xfc */ "\xc3\xbe", /* 0xfd */ "\xc5\xa7",
    /* 0xfe */ "\xc5\x8b", /* 0xff */ "",
};

static bytestring_u t61_to_utf8(const memslice input) {
    bytestring_u output(new bytestring());

    const uint8_t *in = input.cptr();
    for (size_t i = 0; i < input.size(); i++) {
        // Check for invalid characters
        const char* entry = T61Table[in[i]];
        if (!*entry) {
            return nullptr;
        }

        output->append(reinterpret_cast<const uint8_t*>(entry));
    }

    return output;
}

/**
 * iconv() context;  this class allows to use RAII to automatically call
 * iconv_close() whenver that's necessary.
 */
class IconvContext {
    public:
        iconv_t value;

        /**
         * Initialize context.  Note that the constructor flips the order of
         * iconv_open() arguments into natural (from, to) one.
         */
        IconvContext(const char *from, const char *to) {
            value = iconv_open(to, from);
        }

        ~IconvContext() {
            if (*this) {
                iconv_close(value);
            }
        }

        operator iconv_t() { return value; }
        operator bool() { return value != ((iconv_t)-1); }
};

/**
 * Buffer used to store iconv() output in cases where iconv() is only used for
 * validation and the data ends up discarded.
 */
#define DISCARD_BUFFER_SIZE   1024
static char iconv_discard_buffer[DISCARD_BUFFER_SIZE];

/**
 * Validate UTF-8 using iconv().
 */
static bool validate_utf8(const memslice str) {
    // There is a story about why iconv() accepts char** input instead of cosnt
    // char**.  See https://sourceware.org/bugzilla/show_bug.cgi?id=2962
    char *input = const_cast<char *>(str.ccharptr());
    size_t input_size = str.size();

    char *output_buffer_ptr = iconv_discard_buffer;
    size_t output_buffer_size = DISCARD_BUFFER_SIZE;

    IconvContext context("utf-8", "utf-8");
    if (!context) {
        return false;
    }

    while (input_size != 0) {
        size_t return_value = iconv(context, &input, &input_size,
                                    &output_buffer_ptr, &output_buffer_size);
        if (return_value == ((size_t)-1)) {
            if (errno != E2BIG) {
                return false;
            }
        }

        output_buffer_ptr = iconv_discard_buffer;
        output_buffer_size = DISCARD_BUFFER_SIZE;
    }

    return true;
}

static inline bool is_ascii_character(char c) {
    return !(c & 0x80);
}

static inline bool is_t61_character(char c) {
    return *T61Table[(uint8_t)c];
}

/**
 * ASN.1 defines numeric characters as digits and space.
 */
static bool is_numeric_character(char c) {
    return c == ' ' || (c >= '0' && c <= '9');
}

/**
 * Printable characeters here refers to table 10 of X.680 standard.
 */
static bool is_printable_character(char c) {
    if (!is_ascii_character(c)) {
        return false;
    }

    // While isalnum() can be locale-dependant and accept some accented
    // characeters, we run it on ASCII character only, so this should work
    // properly (unless your locale uses EBCDIC, but then you probably have
    // greater problems than that)
    if (isalnum(c)) {
        return true;
    }

    // Note that while '*' is not allowed in specification, real-world X.509
    // certificates are not aware of that nuance, so we have to accept that as
    // well
    if (strchr(" \'()+,-./:=?*", c)) {
        return true;
    }

    return false;
}

bool TextData::validate() {
    const char *str = body.ccharptr();
    const char *str_end = body.ccharptr() + body.size();
    switch (univ_type) {
        /* For UTF-8, use proper validation */
        case UTUTF8String:
            if (options.validate_utf8) {
                return validate_utf8(body);
            } else {
                return true;
            }

        /* Numeric string means digits or space */
        case UTNumericString:
            return std::all_of(str, str_end, is_numeric_character);

        /* Printable strings as defined explicitly in the specification */
        case UTPrintableString:
            return std::all_of(str, str_end, is_printable_character);

       /**
        * Teletex strings have limitations on which characters they may
        * contain, while Latin-1 just encompasses entire range.
        */
        case UTTeletexString:
            if (options.treat_teletex_as_latin1) {
                return true;
            } else {
                return std::all_of(str, str_end, is_t61_character);
            }

        case UTASCIIString:
            // FIXME: reconsider what can actually be in an ASCII string as meant by
            // the specifciation as opposed to common sense

            return std::all_of(str, str_end, is_ascii_character);

        /**
         * We could possibly check for surrogate pairs here, or other
         * codepoints which should never be in a valid Unicode string.  X.680,
         * however, is ambiguous on what BMPString actually is and whether it
         * is restricted to BMP or is just plain UTF-16.
         *
         * I could have possibly come up with a good interpretation of what the
         * specification means, but given how little used are those string
         * types, this is far from a priority issue.
         */
        case UTUniversalString:
        case UTBMPString:
            return true;

        default:
            /* Type unknown => can't validate => not valid */
            return false;
    }
}

/**
 * Maps universal types with corresponding iconv() encoding names.
 *
 * TODO: check how well those codes work on OS X and FreeBSD.
 */
static const char *get_encoding_by_type(UniversalType type, bool treat_teletex_as_latin1) {
    switch (type) {
        case UTTeletexString:
            if (treat_teletex_as_latin1) {
                return "latin1";
            } else {
                // FIXME: should be asserted as unreachable
                return "T.61";
            }

        /**
         * The specification refers to ISO/IEC 10646-1 sections 13.1 and 13.2
         * in 2000 version of the standard;  I was unable to find that version,
         * and 2013 version have different section numbering.  In reality, most
         * of the BMPString fields I have seen are big endian, and all seven
         * occurrences of UniversalString in Google's CT log are big endian
         * (also, all those occurences have two highest bytes set to zeroes in
         * each codepoint, so they could have been just BMPStrings).
         *
         * Some BMPString fields actually have a BOM;  this parser does not
         * handle BOM's and it's up to the consumer to determine what to do
         * with them.
         */
        case UTUniversalString:
            return "utf-32be";
        case UTBMPString:
            return "utf-16be";
        default:
            return "";
    }
}

bytestring_u TextData::to_utf8() {
    if (body.size() == 0) {
        return bytestring_u(new bytestring(""));
    }

    switch (univ_type) {
        /* Valid ASCII or UTF-8, no need for conversion */
        case UTUTF8String:
        case UTNumericString:
        case UTPrintableString:
        case UTASCIIString:
            return bytestring_u(new bytestring(body));

        /* If we actually are parsing T.61, use built-in routines */
        case UTTeletexString:
            if (!options.treat_teletex_as_latin1) {
                return t61_to_utf8(body);
            }

        /* Needs charset conversion, use iconv() */
        case UTUniversalString:
        case UTBMPString: {
            IconvContext context(
                get_encoding_by_type(univ_type, options.treat_teletex_as_latin1),
                "utf-8");
            if (!context) {
                return nullptr;
            }

            // Here we assume that UTF-8 is at most twice larger than original.
            // This is obviously true for UTF-16 and UTF-32, and should be also
            // true for T.61.
            bytestring_u output(new bytestring(body.size() * 2));
            size_t iconv_output;
            size_t input_size = body.size();
            size_t output_size = output->size();
            const char *input_ptr = body.ccharptr();
            char *output_ptr = output->charptr();

            iconv_output = iconv(context, const_cast<char **>(&input_ptr),
                                 &input_size, &output_ptr, &output_size);
            if (iconv_output == ((size_t)-1)) {
                return nullptr;
            }

            output->resize(output->size() - output_size);
            return output;
        }

        default:
            return nullptr;
    }
}

}
