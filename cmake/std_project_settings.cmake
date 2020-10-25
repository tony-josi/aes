
# Sets default build type as Debug if none was specified

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type as Debug as none was specified")

    # Set defualt build type ad Debug and enable force update of cache so that the previous build config is overwritten
    set(CMAKE_BUILD_TYPE 
        Debug
        CACHE STRING "Choose preferred build type" FORCE)       # String and annotation is for cmake GUI's

    # Set the possible values of build type for cmake-gui, ccmake
    set_property(
        CACHE CMAKE_BUILD_TYPE
        PROPERTY STRINGS
                    "Debug"
                    "Release"
                    "MinSizeRel"
                    "RelWithDebInfo")
endif()

# Generate compile_commands.json to make it easier to work with clang based tools
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Option for Inter - procedural optimization [ENABLE_IPO], defualts to OFF
option(ENABLE_IPO "Enable Interprocedural Optimization, aka Link Time Optimization (LTO)" OFF)

if(ENABLE_IPO)
  include(CheckIPOSupported)        # Internal module of cmake to check for IPO feature
  check_ipo_supported(              # check_ipo_supported() of CheckIPOSupported module
    RESULT
    result
    OUTPUT
    output)
  if(result)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)    # Enable IPO if available
  else()
    message(SEND_ERROR "IPO is not supported: ${output}")
  endif()
endif()
