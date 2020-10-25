
option(LOW_LEVEL_API_SAMPLE "Enable low level api sample" OFF)
option(PROCESS_FILE_EXE "Build exe for file enc/dec" ON)

include_directories(../inc)

add_subdirectory(aes)

if(LOW_LEVEL_API_SAMPLE)
    message("Builds low level API sample")
    set(SOURCES test_main.cpp)  
    add_executable(aes_sample_exe ${SOURCES})
    target_link_libraries(
        aes_sample_exe  
        project_options 
        project_warnings 
        aes_lib 
        ${CMAKE_THREAD_LIBS_INIT})
endif()

if(PROCESS_FILE_EXE)
    message("Builds exe for file enc/dec application")
    set(SOURCES process_file.cpp)  
    add_executable(aes_exe ${SOURCES})
    target_link_libraries(
        aes_exe  
        project_options 
        project_warnings 
        aes_lib 
        ${CMAKE_THREAD_LIBS_INIT})
endif()
