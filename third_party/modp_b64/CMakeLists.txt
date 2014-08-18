# This file is made in order to integrate modp_b64 library with libseal
# buildsystem

cmake_minimum_required(VERSION 2.8)

project(modp_b64)

add_library(
	modp_b64

	STATIC

	modp_b64.cc
)
