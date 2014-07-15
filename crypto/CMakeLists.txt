include_directories(..)

add_subdirectory(common)
add_subdirectory(cipher)
add_subdirectory(testutils)

add_library(
	crypto
	STATIC

	$<TARGET_OBJECTS:crypto_common>
	$<TARGET_OBJECTS:crypto_cipher>
	$<TARGET_OBJECTS:crypto_cipher_aes>
	$<TARGET_OBJECTS:crypto_cipher_rc4>
)
target_link_libraries(crypto intel_aesni)
