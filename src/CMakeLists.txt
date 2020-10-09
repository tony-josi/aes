cmake_minimum_required(VERSION 3.0)

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Ofast)                     # Optimization Level
    # add_compile_options(-ggdb3)                   # Debug symbols
    add_compile_options(-Wpedantic -Wall -Wextra)
    add_compile_options(-Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization) 
    add_compile_options(-Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs) 
    add_compile_options(-Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow)
    add_compile_options(-Wsign-conversion -Wsign-promo -Wstrict-overflow=2 -Wswitch-default) 
    add_compile_options(-Wundef -Wno-unused -pedantic-errors -Wextra -Waggregate-return)
    add_compile_options(-Wcast-align -Wcast-qual -Wconversion -Wdisabled-optimization -Wfloat-equal)
    add_compile_options(-Wformat=2 -Wformat-nonliteral -Wformat-security  -Wformat-y2k)  
    add_compile_options(-Wimport  -Winit-self  -Winline -Winvalid-pch -Wlong-long) 
    add_compile_options(-Wmissing-field-initializers -Wmissing-format-attribute -Wmissing-include-dirs)
    add_compile_options(-Wmissing-noreturn -Wpacked -Wpointer-arith -Wredundant-decls -Wshadow) 
    add_compile_options(-Wstack-protector -Wstrict-aliasing=2 -Wswitch-default -Wswitch-enum)
    add_compile_options(-Wunreachable-code -Wunused -Wunused-parameter -Wvariadic-macros -Wwrite-strings)
endif()

include_directories(../inc)

set(SOURCES aes.cpp)

add_library(aes_lib STATIC ${SOURCES})
