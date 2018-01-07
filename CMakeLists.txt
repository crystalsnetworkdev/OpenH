
# minimum cmake version
cmake_minimum_required(VERSION 3.0.2)

# project name
project(OpenHL)

# set include directory
include_directories(include)

# set binaries directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

# set library directory
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY lib)

# set compiler flags
set(CMAKE_C_FLAGS "-Wall -O3 -march=native")

# set source files
set(SRC_OPENHL_SHA src/sha/sha1.c src/sha/sha2.c)
set(SRC_OPENHL_MD src/md/md4.c src/md/md5.c)

# openhl library
add_library(openhl STATIC ${SRC_OPENHL_SHA} ${SRC_OPENHL_MD})

# sha example
add_executable(example_sha examples/example_sha.c)
target_link_libraries(example_sha openhl)

# md5 example
add_executable(example_md examples/example_md.c)
target_link_libraries(example_md openhl)

# installation
install(DIRECTORY include/openhl DESTINATION include)
install(TARGETS openhl ARCHIVE DESTINATION lib)

