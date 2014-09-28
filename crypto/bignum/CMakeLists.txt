include_directories(../..)

add_library(
	crypto_bignum

	OBJECT

	arith.cc
	convert.cc
)

function(add_test_data data_type dest)
    add_custom_command(
        OUTPUT ${dest}
        COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/test_gen.py ${data_type} > ${dest}
        DEPENDS test_gen.py
    )
endfunction()

add_test_data(add test-data-add.txt)
add_test_data(mul test-data-mul.txt)

add_executable(
	bignum_tests

	tests.cc
    test-data-add.txt
    test-data-mul.txt
)
target_link_libraries(bignum_tests crypto)
target_link_libraries(bignum_tests crypto_testutils)
