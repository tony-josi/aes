cmake_minimum_required(VERSION 3.0)

include_directories(../../inc)

set(SOURCES aes_test.cpp)

add_executable(test_aes ${SOURCES})

target_link_libraries(test_aes 
        project_options 
        project_warnings 
        aes_lib gtest)
