cmake_minimum_required(VERSION 2.8)

project (ponyssl)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -ggdb -std=c++11")
endif()

add_subdirectory(third_party)
add_subdirectory(crypto)
add_subdirectory(asn1)
