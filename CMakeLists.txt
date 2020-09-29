cmake_minimum_required(VERSION 3.0)

project(aes VERSION 1.0)

set(CMAKE_BUILD_TYPE Debug)

# set(CMAKE_CXX_COMPILER "clang")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(MSVC)
    add_compile_options(/W4)
else()
    # add_compile_options(-Ofast)                     # Optimization Level
    # add_compile_options(-ggdb3)                   # Debug symbols
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

set(SOURCES test_main.cpp)

add_executable(aes_exe ${SOURCES})

target_link_libraries(aes_exe aes_lib)
