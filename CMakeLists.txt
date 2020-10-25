cmake_minimum_required(VERSION 3.15)

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


