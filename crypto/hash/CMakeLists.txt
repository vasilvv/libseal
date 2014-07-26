include_directories(../..)

add_library(
	crypto_hash

	OBJECT

    hmac.cc
)

add_subdirectory(md5)
add_subdirectory(sha1)
