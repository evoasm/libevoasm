cmake_minimum_required(VERSION 3.0)
project(libevoasm C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}\
    -std=c11\
    -pedantic -fstrict-aliasing\
    -Wextra -Wall -Wno-unused-label -Wuninitialized\
    -Wswitch-default  -Wstrict-aliasing=3 -Wunreachable-code\
    -Wundef -Wpointer-arith -Wwrite-strings -Wconversion -Winit-self -Wno-unused-parameter")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DEVOASM_MIN_LOG_LEVEL=EVOASM_LOG_LEVEL_DEBUG")

include_directories(${CMAKE_SOURCE_DIR}/src)

set(SOURCE_FILES
        src/evoasm-alloc.c
        src/evoasm-alloc.h
        src/evoasm-arch.c
        src/evoasm-arch.h
        src/evoasm-bitmap.h
        src/evoasm-buf.c
        src/evoasm-buf.h
        src/evoasm-error.c
        src/evoasm-error.h
        src/evoasm-log.c
        src/evoasm-log.h
        src/evoasm-misc.c
        src/evoasm-misc.h
        src/evoasm-param.c
        src/evoasm-param.h
        src/evoasm-search.c
        src/evoasm-search.h
        src/evoasm-util.h
        src/evoasm.c
        src/evoasm.h
        src/evoasm-x64.c
        src/evoasm-x64.h
        src/gen/evoasm-x64-misc.c
        src/gen/evoasm-x64-insts.c src/evoasm-dyn-struct.c src/evoasm-dyn-struct.h)

add_library(evoasm SHARED ${SOURCE_FILES})