libseal: why and how
====================

In the software development community it is generally acknowledged that one
should never write their own cryptographic software.  Vast majority of good
programmers follow that rule; and well, if it's not *good* programmers who
write your crypto... in best case, it is written by mathematicians rather than
programmers.

I honestly tried to do some work on improving BoringSSL before deciding to
write my own TLS implementation;  the conclusion was that C is not really a
language in which your SSL library should be written.  While having an already
working codebase is an advantage which should not be underestimated, the
feeling that the code in question would take much less space in almost any
other language was very demotivating; this is pretty much the reason why this
library exists.

The goal of this library is to be a realistic replacement of OpenSSL or NSS.
There are a lot of TLS libraries out there, but which of them are a realistic
replacement?  I am sure there is an implementation of TLS in Haskell, which has
no issues with memory usage and the high quality of code expected in Haskell
community.  Will you trust a program in lazy language to do constant-time
crypography correctly?  How will you even link it against other problems?
Redistribute onto all those platforms you need to support?

In general, the ability to use the library in a browser like Chrome or Firefox
is a good, and probably most important criteria of whether libseal should do or
not do something.  You could use Go TLS library, which is probably the closest
to a well-written mature TLS library we have; but bridging garbage-collected Go
code with browser's C++ codebase is a poor and fragile construct.  Rust is
probably the best candidate to be the language the TLS library of the future,
but in its current state it can't even promise that it "won't eat your
laundry".  Realistically, if you want to replace OpenSSL, you need to write in
a statically typed non-garbage collected language with wide platform support,
which leaves only C and C++ as options.

The reason why C/C++ libraries other than OpenSSL and NSS are not a practical
option is that, while many of them are fairly well-written, they miss critical
compatibility features and mitigation of attacks on TLS that appeared in
OpenSSL and NSS because browser and web server vendors both needed those fixes
and had resources to make them.  Many crypto libraries out there are kitchen
sinks of different cryptographic primitives and protocols: they do many things,
but few of them is actually of production quality.  The goal of this library is
to support TLS and to support it well: support common extensions,
renegotiation, client auth, constant-time AES-CBC (mitigation for padding
oracles and Lucky-13), SSL 3.0, BEAST mitigation, etc.  This does not mean that
there is no place for support of less used platforms or that all code has to be
relevant to TLS directly;  even within a web browser, TLS is not the only part
that uses cryptography (WebCrypto supports plenty of things which TLS does not,
like RSA-OAEP).  What this means is that if we ever have support for Kerberos
using CAST6 on SPARC, it should not interfere or introduce any additional
maintenance burden to the code which does TLS using AES on x86, and this will
probably not get merged until everything with TLS support is ready for
real-world use.

Another hard decision is whether to use cryptographic primitives from OpenSSL,
or to write our own.  OpenSSL has implementations of the primitives that work
fast on a wide range of platforms, but it is encumbered by an advertisement
clause and is written in a weird macroassembler system called perlasm; my
current impression is that only one person regularly works on that code or
really understands how it actually works.  The current plan is to use yasm and
x86inc (a set of tools proven to work well in projects like x264 and
ffmpeg/libav) and write the most essential optimization ourselves; it also
possible that the author of most accelerated OpenSSL code would be willing to
license his code under BSD license, which would solve the copyright issue, but
not perlasm one.

Speed is important, but it is more an issue of polish than of having a working
TLS library.  A correctness issue which requires assembly is implementation of
AES and GHASH which does not use lookup tables.  There is [a working
implementation](https://crypto.stanford.edu/vpaes/) of AES for SSSE3 which uses
vector permutations.  If we manage to do that on NEON, we will be able to get
secure AES-GCM on a wide class of ARM devices which do not have hardware AES
support.

An extensive test suite is an important part of the plan.  Regular tests which
check correctness are the minimum.  The more interesting options involve
randomized compatibility tests and compatibility tests with other TLS
libraries.  Tests which can catch timing problems would also be an improvement
over the state-of-art.  While reasonably enforcing constant timing is possible
only when you distinguish public and private data on type level (I have
previously considered using [language-level enforcement of constant timing
constraint](https://github.com/vasilvv/decor/blob/master/SUMMARY.md), but even
if I was sure that that is actually the way to go, that technology is too far
from production-level), there are [automated tools which would detect timing
issues](https://github.com/agl/ctgrind);  we may use them or somehow run actual
timing tests to detect variation of timing due to change of secret data.

Another kind of test we would need is a wide-scale test against existing
servers.  For some cases we can use publicly availiable resources like EFF SSL
Observatory and Certificate Transparency logs.  Realistically though, we would
have to wait until someone with enough resources to run Internet-wide tests
becomes involved.

Will anyone ever use this library?  There is an argument that everybody should
just give up and contribute to OpenSSL, since that's what everybody uses
anyways (Chrome already decided to transition from NSS and even Mozilla is
currently considering that) and nobody would seriously consider switching to
libseal for the same reason nobody seriously considers switching to any other
existing alternative library.  The counterargument here is that none of the
alternative libraries are actually better than OpenSSL, and our very goal here
is to make one that is;  should one actually came close to fruition, replacing
OpenSSL would suddenly become much more realistic from the perspective of
people whose opinions actually matter.

    -- Victor,
  August 18, 2014
