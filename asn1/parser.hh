#ifndef __ASN1_PARSER_HH
#define __ASN1_PARSER_HH

#include "crypto/parser.hh"

#include "asn1/data.hh"
#include "asn1/parser_options.hh"

namespace asn1 {

/**
 * Generic ASN.1 parser.  Subclasses support DER and subset of BER.
 *
 * The parser performs validation of the incoming data, some aspects of which
 * may be made more lenient by setting appropriate parser options.
 *
 * Features not supported include indefinite length, multibyte tag values and
 * encoding switching using control sequences.  Support for those may be added
 * provided that samples of valid use cases from real-life cryptographic
 * applications would be added into the test suite.
 *
 * Memory ownership considerations: this class does not assert the ownership of
 * any copies of data in any form; all parser output contains only pointers to
 * the fragments of the original input memory slice.
 *
 * Timing considerations: this module does not provide any guarantees regarding
 * being constant time.
 */
class Parser : public crypto::BaseParser<Data, crypto::BigEndian> {
  protected:
    const ParserOptions options;
    const bool is_der;

    virtual Data_u parse_core() override;

  public:
    Parser(const memslice source_, const ParserOptions &options_)
        : crypto::BaseParser<Data, crypto::BigEndian>(source_),
          options(options_), is_der(options_.encoding == DER) {};
    virtual ~Parser() {};
};

typedef std::unique_ptr<Parser> Parser_u;

}

#endif  /* __ASN1_PARSER__HH */
