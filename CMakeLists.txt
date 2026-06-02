cmake_minimum_required(VERSION 3.16)
project(oxidizer_ida LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Repository root (assets live at <repo>/angr/rust/analyses/{type_db,flirt_sigs}
# and <repo>/angr/rust/definitions/commit_versions.py).
get_filename_component(_default_repo "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(OXIDIZER_REPO_ROOT "${_default_repo}" CACHE PATH "Oxidizer repo root (for assets)")
set(OXIDIZER_DATA_DIR "${OXIDIZER_REPO_ROOT}/angr/rust/analyses" CACHE PATH "Default data dir")

# ---------------------------------------------------------------------------
# Core library (IDA-independent; portable, host-testable)
# ---------------------------------------------------------------------------
add_library(oxidizer_core STATIC
  src/core/json.cpp
  src/core/demangle.cpp
  src/core/idioms.cpp
  src/core/version_id.cpp
  src/core/typedb.cpp
  src/core/c_render.cpp
)
target_include_directories(oxidizer_core PUBLIC src)
if(NOT MSVC)
  target_compile_options(oxidizer_core PRIVATE -Wall -Wextra)
endif()

# ---------------------------------------------------------------------------
# Host tests + dev tools
# ---------------------------------------------------------------------------
option(OXIDIZER_BUILD_TESTS "Build host tests and tools" ON)
if(OXIDIZER_BUILD_TESTS)
  enable_testing()

  add_executable(test_core tests/test_core.cpp)
  target_link_libraries(test_core PRIVATE oxidizer_core)
  add_test(NAME core_tests COMMAND test_core "${OXIDIZER_REPO_ROOT}")

  add_executable(dump_types tools/dump_types.cpp)
  target_link_libraries(dump_types PRIVATE oxidizer_core)

  add_executable(demangle_cli tools/demangle_cli.cpp)
  target_link_libraries(demangle_cli PRIVATE oxidizer_core)

  # Host syntax-check of the IDA glue against minimal SDK stubs (no real SDK
  # required).  Catches our own C++ mistakes; does not validate against the
  # genuine SDK ABI.
  add_library(oxidizer_glue_syntaxcheck OBJECT EXCLUDE_FROM_ALL
    src/ida/oxidizer_ida.cpp
    src/ida/idiom_hooks.cpp
  )
  target_include_directories(oxidizer_glue_syntaxcheck PRIVATE src tests/ida_stubs)
  target_compile_definitions(oxidizer_glue_syntaxcheck PRIVATE OXIDIZER_WITH_HEXRAYS)
endif()

# ---------------------------------------------------------------------------
# The IDA plugin (requires a real IDA SDK)
# ---------------------------------------------------------------------------
option(OXIDIZER_BUILD_PLUGIN "Build the IDA plugin (requires IDASDK)" OFF)
option(OXIDIZER_WITH_HEXRAYS "Enable Hex-Rays idiom annotation" ON)

if(OXIDIZER_BUILD_PLUGIN)
  set(IDASDK "$ENV{IDASDK}" CACHE PATH "Path to the IDA SDK root")
  if(NOT IDASDK OR NOT EXISTS "${IDASDK}/include/pro.h")
    message(FATAL_ERROR
      "OXIDIZER_BUILD_PLUGIN=ON but IDASDK is not set to a valid SDK "
      "(expected ${IDASDK}/include/pro.h). Set -DIDASDK=/path/to/idasdk.")
  endif()

  set(_plugin_srcs src/ida/oxidizer_ida.cpp)
  if(OXIDIZER_WITH_HEXRAYS)
    list(APPEND _plugin_srcs src/ida/idiom_hooks.cpp)
  endif()

  add_library(oxidizer_plugin MODULE ${_plugin_srcs})
  target_link_libraries(oxidizer_plugin PRIVATE oxidizer_core)
  target_include_directories(oxidizer_plugin PRIVATE src "${IDASDK}/include")

  # IDA expects no "lib" prefix and a platform-specific suffix.
  set_target_properties(oxidizer_plugin PROPERTIES OUTPUT_NAME "oxidizer" PREFIX "")

  # Modern IDA ships a unified 64-bit build (ea64).
  target_compile_definitions(oxidizer_plugin PRIVATE __IDP__ __EA64__
    OXIDIZER_DEFAULT_DATA_DIR="${OXIDIZER_DATA_DIR}")
  if(OXIDIZER_WITH_HEXRAYS)
    target_compile_definitions(oxidizer_plugin PRIVATE OXIDIZER_WITH_HEXRAYS)
  endif()

  if(WIN32)
    target_compile_definitions(oxidizer_plugin PRIVATE __NT__)
    set_target_properties(oxidizer_plugin PROPERTIES SUFFIX ".dll")
    set(_ida_libdir "${IDASDK}/lib/x64_win_vc_64")
    target_link_libraries(oxidizer_plugin PRIVATE "${_ida_libdir}/ida.lib")
  elseif(APPLE)
    target_compile_definitions(oxidizer_plugin PRIVATE __MAC__)
    set_target_properties(oxidizer_plugin PROPERTIES SUFFIX ".dylib")
    # Pick the SDK lib dir matching the build architecture (Apple Silicon vs Intel).
    if(CMAKE_OSX_ARCHITECTURES MATCHES "arm64" OR
       (NOT CMAKE_OSX_ARCHITECTURES AND CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm64|aarch64"))
      set(_ida_libdir "${IDASDK}/lib/arm64_mac_clang_64")
    else()
      set(_ida_libdir "${IDASDK}/lib/x64_mac_clang_64")
    endif()
    if(NOT EXISTS "${_ida_libdir}/libida.dylib")
      message(FATAL_ERROR "No libida.dylib under ${_ida_libdir}; check your SDK arch dirs.")
    endif()
    target_link_libraries(oxidizer_plugin PRIVATE "${_ida_libdir}/libida.dylib")
  else()
    target_compile_definitions(oxidizer_plugin PRIVATE __LINUX__)
    set_target_properties(oxidizer_plugin PROPERTIES SUFFIX ".so")
    set(_ida_libdir "${IDASDK}/lib/x64_linux_gcc_64")
    target_link_libraries(oxidizer_plugin PRIVATE "${_ida_libdir}/libida.so")
  endif()

  message(STATUS "Oxidizer plugin will link IDA libs from: ${_ida_libdir}")
  message(STATUS "Plugin default data dir: ${OXIDIZER_DATA_DIR}")
endif()
