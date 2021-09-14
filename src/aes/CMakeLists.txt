set(AES_LIB_INC_DIR "${PROJECT_SOURCE_DIR}/inc")
set(AES_LIB_PRIV_INC_DIR "${PROJECT_SOURCE_DIR}/src/aes/aes_inc")
set(SOURCES aes_core.cpp aes_lookup_tables.cpp aes_operations.cpp aes_thread_utils.cpp)


add_library(aes_lib STATIC ${SOURCES})


target_link_libraries(
    aes_lib  
    project_options 
    project_warnings)

target_include_directories(
    aes_lib
    PRIVATE ${AES_LIB_INC_DIR}
    ${AES_LIB_PRIV_INC_DIR}
)
