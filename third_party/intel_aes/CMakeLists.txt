# This file is made in order to integrate Intel AES-NI library with libseal
# buildsystem

cmake_minimum_required(VERSION 2.8)

project(intel_aesni)

enable_language(ASM_NASM)

# FIXME
set(CMAKE_ASM_NASM_COMPILER "/usr/bin/yasm")
set(CMAKE_ASM_NASM_FLAGS "-D__linux__")

include_directories(include)

set_source_files_properties(
	asm/x64/iaesx64.s
	PROPERTIES
	LANGUAGE ASM_NASM
)
add_library(
	intel_aesni

	STATIC

	src/intel_aes.c
	asm/x64/iaesx64.s
)

#add_executable(
#	intel_aesni_sample
#
#	src/aessample.c
#)
#target_link_libraries(intel_aesni_sample intel_aesni)
