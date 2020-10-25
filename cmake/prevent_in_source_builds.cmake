
# This function will prevent building binaries inside the source folders or restrict the build only to build directory

function(prevent_in_source_builds)
    # make sure the user doesn't play dirty with symlinks
    get_filename_component(srcdir "${CMAKE_SOURCE_DIR}" REALPATH)
    get_filename_component(bindir "${CMAKE_BINARY_DIR}" REALPATH)

    # disallow in-source builds
    if("${srcdir}" STREQUAL "${bindir}")
    message("------------------------------------------------------------------")
    message("Warning: in-source builds are disabled")
    message("Please create a separate build directory and run cmake from there")
    message("------------------------------------------------------------------")
    message(FATAL_ERROR "Quitting configuration")
    message("------------------------------------------------------------------")
    endif()
endfunction()