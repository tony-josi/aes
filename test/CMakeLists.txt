
add_subdirectory(gtest)

add_subdirectory(test_files)

target_link_libraries(test_aes 
        project_options 
        project_warnings 
        aes_lib gtest)
