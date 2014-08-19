/**
 * Copyright (C) 2014 The libseal Authors.  All rights reservied.
 *
 * Use of this source code file is governed by MIT license, as stated in the
 * LICENSE file.
 *
 * This file contains the basic ASN.1 data model.
 */

#ifndef __ASN1_DATA
#define __ASN1_DATA

#include <string>
#include <vector>

#include "crypto/common.hh"

#include "asn1/parser_options.hh"

namespace asn1 {

// TODO: support OIDs

using crypto::memslice;
using crypto::bytestring;
using crypto::bytestring_u;

/**
 * One of the four classes of values supported by ASN.1 data model.
 */
enum Class {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3
};

/**
 * Some of the universal types.  Not all of those types are supported by the
 * parsing module.
 */
enum UniversalType {
    UTEndOfContent = 0,
    UTBoolean = 1,
    UTInteger = 2,
    UTBitString = 3,
    UTOctetString = 4,
    UTNull = 5,
    UTOID = 6,
    UTEnum = 10,
    UTUTF8String = 12,
    UTRelativeOID = 13,
    UTSequence = 16,
    UTSet = 17,
    UTNumericString = 18,
    UTPrintableString = 19,
    UTTeletexString = 20,
    UTASCIIString = 22,
    UTUTCTime = 23,
    UTUniversalString = 28,
    UTBMPString = 30,

    /**
     * For reference, here are some figures on which types are actually used in
     * X.509 certificates, gathered by quick parse through CT log:
     *
     * 133651192 [Sequence]
     * 100151848 [OID]
     * 44161334 [Set]
     * 41629335 [Octet String]
     * 40265268 [Printable String]
     * 14356556 [Null]
     * 9571319 [Integer]
     * 9571294 [UTC Time]
     * 9571294 [Bit String]
     * 7668947 [Boolean]
     * 4785642 [CONTEXT-SPECIFIC 3]
     * 4785642 [CONTEXT-SPECIFIC 0]
     * 2608442 [Teletex String]
     * 1016739 [UTF-8 String]
     *  273215 [ASCII String]
     *    1711 [BMP String]
     *       7 [UTF-32 String]
     *
     * The specification uses more types then listed here, but then, you can
     * never be sure what things are actually used, since it defines a lot of
     * things which obviously do not belong to PKIX like "TerminalType" enum
     * (which may assume values like "g4-facsimile", if it's not clear what is
     * meant by that name).
     */
};

/**
 * Returns if certain type has to be a constructed type.
 */
static inline bool is_constructed_type(UniversalType type) {
    return type == UTSequence || type == UTSet;
}

/**
 * Returns if certain type is a text type (this explicitly excludes bitstrings
 * and octet strings).
 */
static inline bool is_text_type(UniversalType type) {
    return type == UTUTF8String || type == UTNumericString ||
           type == UTPrintableString || type == UTTeletexString ||
           type == UTASCIIString || type == UTUniversalString ||
           type == UTBMPString;
}

/**
 * Returns if certain type can be represented as a constructed type in BER.
 */
static inline bool can_be_constructed_type(UniversalType type) {
    return is_constructed_type(type) || is_text_type(type) ||
           type == UTBitString || type == UTOctetString;
}

typedef uint8_t Tag;

/**
 * Representation of the tagged value encoded.  This object does not assert
 * ownership of any memory, and points into the apppropraite chunk of memory in
 * the original fragment being parsed, since such representation is feasible in
 * case of both BER and DER.
 *
 * Some of the universal data types may be represented as subclasses of this
 * class; those subclasses have methods specific to those data types which
 * allow conversion from on-wire representation to the actually useful one.
 */
class Data {
    friend class Parser;

  protected:
    const Tag tag;
    const bool constructed;
    const Class data_class;
    const memslice body;

    Data(Tag tag_, bool constructed_, Class class_, const memslice body_)
        : tag(tag_), constructed(constructed_), data_class(class_),
          body(body_) {};

  public:
    virtual ~Data() {};

    inline const memslice get_body() { return body; }
    inline Class get_class() { return data_class; }
    inline Tag get_tag() { return tag; }
    inline bool is_constructed() { return constructed; }

    inline bool is_universal_type(UniversalType type) {
        return data_class == Universal && ((UniversalType)tag) == type;
    }
    inline bool is_text() {
        return data_class == Universal && is_text_type((UniversalType)tag);
    }

    /**
     * Returns human-readable description of the data type.
     */
    const std::string get_type_desc();
};

typedef std::unique_ptr<Data> Data_u;

/**
 * All data with the "constructed" bit set to 1 are represented using this
 * class.
 */
class ConstructedData : public Data {
    friend class Parser;

  protected:
    std::vector<Data_u> elements;
    ConstructedData(Tag tag_, bool constructed_, Class class_,
                    const memslice body_)
        : Data(tag_, constructed_, class_, body_) {};

  public:
    virtual ~ConstructedData() {};

    inline const std::vector<Data_u> &get_elements() { return elements; }
};

typedef std::unique_ptr<ConstructedData> ConstructedData_u;

/**
 * Boolean ASN.1 type.
 */
class BooleanData : public Data {
    friend class Parser;

  protected:
    BooleanData(Tag tag_, bool constructed_, Class class_, const memslice body_)
        : Data(tag_, constructed_, class_, body_) {};

  public:
    virtual ~BooleanData() {};

    inline bool get() { return *body.cptr(); }
};

/**
 * Represents a text type, that is, a type where the data has the text form and
 * can be meaningfully converted into Unicode.
 *
 * This class represents only primitive string types; in BER, if a string is
 * constructed, assembling it back is up to the consumer.
 */
class TextData : public Data {
    friend class Parser;

  protected:
    const UniversalType univ_type;
    const ParserOptions options;

    TextData(Tag tag_, bool constructed_, Class class_, const memslice body_,
         const ParserOptions &options_)
        : Data(tag_, constructed_, class_, body_),
          univ_type(static_cast<UniversalType>(tag)), options(options_) {};

  public:
    virtual ~TextData() {};

    /**
     * Verifies that the string is properly encoded.  UTF-8 validation might be
     * optionally disabled.
     */
    bool validate();

    /**
     * Return the value of the string as UTF-8.  Returns nullptr if the string
     * is not valid.
     *
     * The resulting string may contain BOM;  handling of this issue is
     * deferred to the caller.
     */
    bytestring_u to_utf8();
};

typedef std::unique_ptr<TextData> TextData_u;

}

#endif  /* __ASN1_DATA */
