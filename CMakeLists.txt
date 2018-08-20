cmake_minimum_required (VERSION 3.5)
project (stpm2 C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic -Werror")

find_package(PkgConfig)
pkg_check_modules(TSS2_SYS REQUIRED tss2-sys)

add_library(
	stpm2
	src/stpm2.c
	src/stpm2_log.c
	src/stpm2_base64.c
	src/imported/tpm2-tools/tpm2_error.c
)
set_property(TARGET stpm2 PROPERTY C_STANDARD 99)

target_include_directories(
	stpm2 PUBLIC
	src
)

target_include_directories(
	stpm2 PRIVATE
	src/imported
	src/imported/tpm2-tools
	${TSS2_SYS_INCLUDE_DIRS}
)

target_link_libraries(
	stpm2
	dl
	${TSS2_SYS_LIBRARIES}
)

# Section for examples
set(STPM2_INCLUDE_DIR src)

add_executable(example_get_random examples/get_random.c)
set_property(TARGET example_get_random PROPERTY C_STANDARD 99)
target_include_directories(example_get_random PRIVATE ${STPM2_INCLUDE_DIR})
target_link_libraries(example_get_random stpm2)

add_executable(example_hash examples/hash.c)
set_property(TARGET example_hash PROPERTY C_STANDARD 99)
target_include_directories(example_hash PRIVATE ${STPM2_INCLUDE_DIR})
target_link_libraries(example_hash stpm2)

add_executable(example_rsa_keys examples/rsa_keys.c)
set_property(TARGET example_rsa_keys PROPERTY C_STANDARD 99)
target_include_directories(example_rsa_keys PRIVATE ${STPM2_INCLUDE_DIR})
target_link_libraries(example_rsa_keys stpm2)
