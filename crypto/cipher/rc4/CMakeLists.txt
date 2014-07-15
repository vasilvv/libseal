include_directories(../../.. ../../../third_party/intel_aes/include)

add_library(
	crypto_cipher_rc4

	OBJECT

	rc4.cc
)

add_executable(
	rc4_tests

	tests.cc
)
target_link_libraries(rc4_tests crypto)
target_link_libraries(rc4_tests crypto_testutils)
