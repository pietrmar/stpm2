cmake_minimum_required (VERSION 3.5)
project (stpm2)

include_directories(src)

add_library(stpm2 src/stpm2.c)
target_link_libraries(stpm2 tss2-sys)

add_executable(example_get_random examples/get_random.c)
target_link_libraries(example_get_random stpm2)

