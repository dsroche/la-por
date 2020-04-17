#
# CMake file for Merkle subdir inside of Integrity project
# Mike Hanling
#

# have the .a stored in build/lib
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

# add include directory for this library
include_directories(include)

# create the static library
add_library(merkle STATIC merkle.c)
