include_directories(..)

add_subdirectory(asm)
add_subdirectory(common)
add_subdirectory(cipher)
add_subdirectory(hash)
add_subdirectory(testutils)

add_library(
	crypto
	STATIC

	$<TARGET_OBJECTS:crypto_asm>
	$<TARGET_OBJECTS:crypto_common>
	$<TARGET_OBJECTS:crypto_cipher>
	$<TARGET_OBJECTS:crypto_cipher_aes>
	$<TARGET_OBJECTS:crypto_cipher_rc4>
	$<TARGET_OBJECTS:crypto_hash>
	$<TARGET_OBJECTS:crypto_hash_md5>
)
target_link_libraries(crypto intel_aesni)
