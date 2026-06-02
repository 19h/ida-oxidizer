cmake_minimum_required(VERSION 3.27 FATAL_ERROR)
project(oxidizer_plugin CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Pull in the IDA SDK's ida-cmake framework (defines generate(), platform macros,
# EA64 handling, libida linkage, plugin output naming, rpath, etc.).
if (DEFINED IDASDK)
    include(${IDASDK}/ida-cmake/idasdk.cmake)
elseif (DEFINED ENV{IDASDK})
    include($ENV{IDASDK}/ida-cmake/idasdk.cmake)
else()
    message(FATAL_ERROR "IDA SDK not specified (-DIDASDK=... or env IDASDK)")
endif()

# The bundled ida-cmake hardcodes the Linux lib dir to x64_linux_gcc_64, which is
# empty in this SDK; libida.so actually lives under x64_linux_clang_64 (or
# x64_linux_64).  Repoint IDALIB64 to whichever exists before generate() uses it.
if(UNIX AND NOT APPLE)
    foreach(_d x64_linux_clang_64 x64_linux_64 x64_linux_gcc_64)
        if(EXISTS "${IDASDK}/lib/${_d}/libida.so")
            set(IDALIB64 "${IDASDK}/lib/${_d}/libida.so")
            message(STATUS "Oxidizer plugin: linking IDA lib ${IDALIB64}")
            break()
        endif()
    endforeach()
endif()

get_filename_component(OXI_SRC "${CMAKE_CURRENT_LIST_DIR}/../src" ABSOLUTE)
get_filename_component(OXI_DATA "${CMAKE_CURRENT_LIST_DIR}/../../angr/rust/analyses" ABSOLUTE)

set(PLUGIN_NAME oxidizer)
set(PLUGIN_SOURCES
    ${OXI_SRC}/core/json.cpp
    ${OXI_SRC}/core/demangle.cpp
    ${OXI_SRC}/core/idioms.cpp
    ${OXI_SRC}/core/version_id.cpp
    ${OXI_SRC}/core/typedb.cpp
    ${OXI_SRC}/core/c_render.cpp
    ${OXI_SRC}/ida/oxidizer_ida.cpp
    ${OXI_SRC}/ida/idiom_hooks.cpp
)
set(PLUGIN_INCLUDE_DIRECTORIES ${OXI_SRC})

generate()
disable_ida_warnings(oxidizer)

# Our own include path + build-time configuration.
target_include_directories(oxidizer PRIVATE ${OXI_SRC})
target_compile_definitions(oxidizer PRIVATE
    OXIDIZER_WITH_HEXRAYS
    OXIDIZER_DEFAULT_DATA_DIR="${OXI_DATA}")

message(STATUS "Oxidizer plugin: data dir = ${OXI_DATA}")
