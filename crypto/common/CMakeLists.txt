include_directories(../.. ../../third_party/modp_b64)

add_library(
	crypto_common

	OBJECT

    base64.cc
	bytestring.cc
)

add_executable(
	parser_tests

	parser_tests.cc
)
target_link_libraries(parser_tests crypto)
target_link_libraries(parser_tests crypto_testutils)

add_executable(
	base64_tests

	base64_tests.cc
)
target_link_libraries(base64_tests crypto)
target_link_libraries(base64_tests crypto_testutils)
