#
# CMake file for TinyMT subdir inside of Integrity project
# Mike Hanling
#

# have the .a stored in build/lib
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

# add include path for this library
include_directories(include)

# create the static library
add_library(tinymt64 STATIC tinymt64.c)
