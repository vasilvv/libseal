include_directories(../../.. ../../../third_party/intel_aes/include)

add_library(
	crypto_cipher_aes

	OBJECT

	aes.cc
	rijndael-alg-fst.cc
)

add_executable(
	aes_tests

	tests.cc
)
target_link_libraries(aes_tests crypto)
target_link_libraries(aes_tests crypto_testutils)
