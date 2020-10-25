include_directories(../inc)

add_subdirectory(aes)

set(SOURCES process_file.cpp)  # TODO: set build options for test_main as well

add_executable(aes_exe ${SOURCES})
target_link_libraries(aes_exe aes_lib ${CMAKE_THREAD_LIBS_INIT})
