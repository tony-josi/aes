set(SOURCES aes.cpp)
add_library(aes_lib STATIC ${SOURCES})

target_link_libraries(
    aes_lib  
    project_options 
    project_warnings)
