cmake_minimum_required(VERSION 3.0)

include_directories(../../inc)

set(SOURCES aes_test.cpp)

# add_subdirectory(../../src)

# add_subdirectory(../gtest)

add_executable(test_aes ${SOURCES})

target_link_libraries(test_aes aes_lib gtest)
