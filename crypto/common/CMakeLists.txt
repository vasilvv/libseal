include_directories(../..)

add_library(
	crypto_common

	OBJECT

	bytestring.cc
)

add_executable(
	parser_tests

	parser_tests.cc
)
target_link_libraries(parser_tests crypto)
target_link_libraries(parser_tests crypto_testutils)
