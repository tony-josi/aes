cmake_minimum_required(VERSION 3.12)

project(aes VERSION 2.0 DESCRIPTION "Aes Library" HOMEPAGE_URL https://github.com/TonyJosi97/aes LANGUAGES CXX)

include(cmake/std_project_settings.cmake)

include(cmake/prevent_in_source_builds.cmake)
prevent_in_source_builds()

# TODO: cache settings

# Set CXX standard
add_library(project_options INTERFACE)
target_compile_features(project_options INTERFACE cxx_std_17)

# Set CXX compile flags
include(cmake/std_compiler_warnings.cmake)
add_library(project_warnings INTERFACE)
set_project_warnings(project_warnings)

if(ENABLE_TESTING)
    enable_testing()
    message("Building Tests.")
    add_subdirectory(test)
    add_test(
        NAME AES_ENC_DEC_TESTS
        COMMAND test_aes
    )
endif()


# pybind11
option(PYTHON_BINDINGS_GEN "Enable python binding module generation" OFF)
if(PYTHON_BINDINGS_GEN) 
    set(PYBIND_PATH "${PROJECT_SOURCE_DIR}/ext_py_binding_lib")
    add_subdirectory(${PYBIND_PATH}/pybind11)
endif()

add_subdirectory(src)


