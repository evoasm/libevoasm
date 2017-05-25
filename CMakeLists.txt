cmake_minimum_required(VERSION 3.1)
project(evoasm C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}\
    -pedantic -fstrict-aliasing\
    -Wextra -Wall -Wno-unused-label -Wuninitialized\
    -Wswitch-default  -Wstrict-aliasing=3 -Wunreachable-code\
    -Wundef -Wpointer-arith -Wwrite-strings -Wconversion -Winit-self -Wno-unused-parameter")

set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb3 -DEVOASM_LOG_LEVEL=EVOASM_LOG_LEVEL_DEBUG")
set(CMAKE_C_STANDARD 11)

add_definitions("-DEVOASM_ENABLE_PARANOID_MODE")

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
        src/evoasm-rand.c
        src/evoasm-rand.h
        src/evoasm-param.c
        src/evoasm-param.h
        src/evoasm-util.h
        src/evoasm.c
        src/evoasm.h
        src/evoasm-x64.c
        src/evoasm-x64.h
        src/gen/evoasm-x64-misc.c
        src/gen/evoasm-x64-insts.c
        src/gen/evoasm-x64-params.c
        src/gen/evoasm-x64-params.h
        src/gen/evoasm-x64-enums.h
        src/evoasm-domain.h
        src/evoasm-domain.c
        src/evoasm-pop-params.h
        src/evoasm-pop-params.c
        src/evoasm-kernel.c
        src/evoasm-kernel.h
        src/evoasm-pop.c
        src/evoasm-pop.h
        src/evoasm-signal.c
        src/evoasm-signal.h
        src/evoasm-kernel-io.c
        src/evoasm-kernel-io.h)

find_package(Threads)
find_package(OpenMP)
if(OPENMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

add_library(evoasm SHARED ${SOURCE_FILES})
target_link_libraries(evoasm ${CMAKE_THREAD_LIBS_INIT})

