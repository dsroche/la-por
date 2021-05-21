#
# CMake file for cleaned up Integrity project
# Mike Hanling
#

cmake_minimum_required(VERSION 3.13)

# define project
project(integrity VERSION 0.1
	DESCRIPTION "matrix-based PoR scheme"
	LANGUAGES C
	)

# find required libraries (ssl and crypto combined)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(OpenMP 4.5 REQUIRED)

# set variables
set(CC "gcc")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Ofast -march=native -std=gnu99 -Wno-missing-prototypes -DNDEBUG -Wno-unused -g")
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# link merkle subdir
add_subdirectory(merkle)
add_subdirectory(tinymt64)

# allow CMake to see the header files
include_directories(include merkle/include tinymt64/include ${OPENSSL_INCLUDE_DIRS})

# variable SOURCES now holds all of the executables desired
# file(GLOB SOURCES "src/*.c")

# declare executables
set(EXECS client server dual_init random_file)
foreach(EXEC IN LISTS EXECS)
	add_executable(${EXEC} src/${EXEC}.c)
	target_link_libraries(${EXEC} merkle)
	target_link_libraries(${EXEC} tinymt64)
	target_link_libraries(${EXEC} ${OPENSSL_LIBRARIES})
	target_link_libraries(${EXEC} m)
	target_link_libraries(${EXEC} OpenMP::OpenMP_C)
endforeach()
