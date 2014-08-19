#ifndef __ASN1_OID_HH
#define __ASN1_OID_HH

#include "crypto/common.hh"

#include <memory>
#include <vector>

namespace asn1 {

using crypto::bytestring;
using crypto::memslice;

// I am not aware of any OIDs of a practical interest where a component is
// larger than 2^32.  Should one appear, we can bump this to uint64_t.
typedef uint32_t OIDComponent;

typedef std::vector<OIDComponent> OIDComponents;
typedef std::unique_ptr<OIDComponents> OIDComponents_u;

/**
 * Represents an object identifier (OID).
 *
 * The OID is stored in the format DER represents it on the wire.
 */
class OID {
  private:
      bytestring der;
  public:
      /**
       * Initialize the object from DER representation.
       */
      OID(const bytestring &der_) : der(der_) {};
      OID(const memslice der_) : der(der_) {};

      /**
       * Initialize the object from the component number.  Note that OID must
       * have at least two components.
       */
      OID(const std::initializer_list<OIDComponent> components);

      /**
       * Return the on-wire DER representation.
       */
      inline bytestring get_der() const { return der; }

      /**
       * Return the representation of OID as an array of individual components,
       * or null if OID is too large to represent and hence is probably bogus.
       */
      OIDComponents_u get_components() const;

      /**
       * Returns whether the OID in question is a valid OID.
       */
      inline bool validate() const { return static_cast<bool>(get_components()); }

      /**
       * Returns component representation of OID as string of numbers separated
       * by dots.
       */
      std::string to_string() const;

      inline bool operator==(const OID& other) const {
          return der == other.der;
      }
      inline bool operator!=(const OID& other) const {
          return der != other.der;
      }
};

}

#endif /* __ASN1_OID_HH */
