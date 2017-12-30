
# minimum cmake version
cmake_minimum_required(VERSION 2.8.3)

# project name
project(OpenHL)

# set include directory
include_directories(include)

# set binaries directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

# set library directory
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY lib)

# set compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O3 -march=native")

# set source files
set(SRC_OPENHL src/sha.c)

# openhl library
add_library(openhl STATIC ${SRC_OPENHL})

# sha example
add_executable(example_sha examples/example_sha.c)
target_link_libraries(example_sha openhl)

