include_directories(../../..)

add_library(
	crypto_hash_sha1

	OBJECT

	sha1.cc
)

add_executable(
	sha1_tests

	tests.cc
)
target_link_libraries(sha1_tests crypto)
target_link_libraries(sha1_tests crypto_testutils)
