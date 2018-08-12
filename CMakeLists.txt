cmake_minimum_required (VERSION 3.5)
project (stpm2)

add_definitions(-DLOG_USE_COLOR)

include_directories(
	src
	src/imported
	src/imported/tpm2-tools
	src/imported/log.c/src
)

add_library(
	stpm2
	src/stpm2.c
	src/imported/tpm2-tools/tpm2_error.c
	src/imported/log.c/src/log.c
)
target_link_libraries(stpm2 tss2-sys dl)

add_executable(example_get_random examples/get_random.c)
target_link_libraries(example_get_random stpm2)

add_executable(example_hash examples/hash.c)
target_link_libraries(example_hash stpm2)

add_executable(example_create_primary examples/create_primary.c)
target_link_libraries(example_create_primary stpm2)
