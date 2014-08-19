include_directories(..)

add_library(
	asn1
	STATIC

    data.cc
    oid.cc
    parser.cc
    text.cc
    time.cc
)
target_link_libraries(asn1 crypto)

add_executable(
    oid_tests

    oid_tests.cc
)
target_link_libraries(oid_tests asn1)
target_link_libraries(oid_tests crypto_testutils)

add_executable(
    asn1_cli

    test.cc
)
target_link_libraries(asn1_cli asn1)
