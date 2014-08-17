#include "asn1/data.hh"

namespace asn1 {

const std::string Data::get_type_desc() {
    if (data_class == Universal) {
        switch ((UniversalType)tag) {
            case UTEndOfContent:
                return "End of Content";
            case UTBoolean:
                return "Boolean";
            case UTInteger:
                return "Integer";
            case UTBitString:
                return "Bit String";
            case UTOctetString:
                return "Octet String";
            case UTNull:
                return "Null";
            case UTOID:
                return "OID";
            case UTEnum:
                return "Enumeration";
            case UTUTF8String:
                return "UTF-8 String";
            case UTRelativeOID:
                return "Relative OID";
            case UTSequence:
                return "Sequence";
            case UTSet:
                return "Set";
            case UTNumericString:
                return "Numeric String";
            case UTPrintableString:
                return "Printable String";
            case UTTeletexString:
                return "Teletex String";
            case UTASCIIString:
                return "ASCII String";
            case UTUTCTime:
                return "UTC Time";
            case UTUniversalString:
                return "UTF-32 String";
            case UTBMPString:
                return "BMP String";
            default:
                /* Handled below */
                break;
        }
    }

    const char *class_str;
    switch (data_class) {
        case Universal:
            class_str = "UNIVERSAL";
            break;
        case Application:
            class_str = "APPLICATION";
            break;
        case ContextSpecific:
            class_str = "CONTEXT-SPECIFIC";
            break;
        case Private:
            class_str = "PRIVATE";
            break;
        default:
            class_str = "?????";
            break;
    }

    return std::string(class_str) + " " + std::to_string(tag);
}

}
