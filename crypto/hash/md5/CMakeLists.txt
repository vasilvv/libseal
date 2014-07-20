include_directories(../../..)

add_library(
	crypto_hash_md5

	OBJECT

	md5.cc
)

add_executable(
	md5_tests

	tests.cc
)
target_link_libraries(md5_tests crypto)
target_link_libraries(md5_tests crypto_testutils)
