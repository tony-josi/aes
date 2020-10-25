
add_subdirectory(gtest)

add_subdirectory(test_files)

target_link_libraries(test_aes aes_lib gtest)
