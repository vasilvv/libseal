include_directories(../..)

add_library(
	crypto_cipher

	OBJECT

    modes.cc
)

add_subdirectory(aes)
add_subdirectory(rc4)
