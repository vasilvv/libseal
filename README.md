libseal (Secure Encryption and Authentication Library)
======================================================

libseal is a C++11 implementation of Transport Layer Security protocol.

The aim of this project is to create a library which:
1. is feasible to integrate with existing software,
2. uses modern software development techniques to avoid regressions and memory
   management issues,
3. is not encumbered by absurd unmaintained chunks of code, like support for
   arcane platforms, abandoned expermintal TLS extensions, random #if-0'd
   debugging core,
4. has reasonably straightforward design, which does not use class formed by a
   class tree of 8 other classes in order to implement SHA-1, or pretends all
   cryptograhpic interfaces are PKCS#11.
5. is not encumbered by licensing issues,

In other words, this library was started because in spite of seeming abundance
of TLS libraries out there, OpenSSL turned out to be the right answer for most
practical use cases, and NSS was usually the second answer.  The details of the
motivation behind this project, as well as more details on how exactly we
intend to achieve these goals, are in PLAN.md.

This library is currently work in progress;  it has features missing, and there
is a lot of work to be done.  All internal APIs are unstable, and you very much
should not be using it for anything real yet.

Currently, it contains the following components:
* asn1/ -- ASN.1 parsing and generation
* crypto/ -- cryptographic primitives and basic utility code
* third\_party/ -- third-party components used by the library

In order to build library, create build/ directory and run `cmake ..'.  You
will need CMake 2.8.8+.  The current version probably only works on Linux with
AMD64 CPU, but support for different operating systems and architectures are
definitely part of the plan.
