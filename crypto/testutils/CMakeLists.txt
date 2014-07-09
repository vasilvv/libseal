include_directories(../..)

add_library(
	crypto_testutils

	STATIC

	compat_tester.cc
)
target_link_libraries(crypto_testutils gtest)
