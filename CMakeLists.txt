cmake_minimum_required(VERSION 3.0)

project(aes VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wpedantic -Wall -Wextra)
endif()

include_directories(inc)

add_subdirectory(src)

message("TEST_EN=${TEST_EN}")
if( TEST_EN ) 
    message("Testing Enabled")
    enable_testing()
    add_subdirectory(test)
    add_test(
        NAME AES_ENC_DEC_TESTS
        COMMAND test_aes
    )
endif()

find_package (Threads)

set(SOURCES test_main.cpp)

add_executable(aes_exe ${SOURCES})

target_link_libraries(aes_exe aes_lib ${CMAKE_THREAD_LIBS_INIT})
