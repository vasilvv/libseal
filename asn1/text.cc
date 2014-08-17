#include "asn1/data.hh"

#include <ctype.h>
#include <iconv.h>

#include <algorithm>

namespace asn1 {

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

bool Text::validate() {
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
        * We do not reject any TeletexString values because, while T.61 has
        * characters which are invalid, TeletexString secretly always mean
        * Latin-1.  Now, Latin-1 also has characters which are not valid, but
        * invalid T.61 strings and invalid Latin-1 strings do not intersect, so
        * we defer the validation until the stage where the consumer gets
        * actually interested in interpreting the string as one of those two
        * options.
        */
        case UTTeletexString:
            return true;

        case UTASCIIString:
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

bytestring_u Text::to_utf8() {
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

        /* Needs charset conversion, use iconv() */
        case UTTeletexString:
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
