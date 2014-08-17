include_directories(..)

add_library(
	asn1
	STATIC

    data.cc
    parser.cc
    text.cc
)
target_link_libraries(asn1 crypto)
