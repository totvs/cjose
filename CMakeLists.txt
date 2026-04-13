cmake_minimum_required(VERSION 3.15)
# Version updated to reflect the latest autotools release (0.6.2.4)
project(cjose VERSION 0.6.2.4 LANGUAGES C)

include(CheckSymbolExists)
include(CheckTypeSize) 
include(CheckIncludeFile)
include(GNUInstallDirs)

# --- Build Options ---
option(ENABLE_TESTS "Enable unit tests" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_RSA_PKCS1_5 "Enable risky RSA PKCS v1.5 padding" OFF)

# --- Output Directories ---
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# Generate version header
configure_file(
    "${PROJECT_SOURCE_DIR}/include/cjose/version.h.in"
    "${PROJECT_BINARY_DIR}/include/cjose/version.h"
)

# --- Flexible Dependency Resolution ---

# OpenSSL
if(OPENSSL_INCLUDE_DIR AND OPENSSL_LIBRARIES)
    message(STATUS "CJOSE: Using manually provided OpenSSL paths.")
else()
    # If OPENSSL_ROOT_DIR is provided, find_package will use it as a hint
    find_package(OpenSSL 1.0.1 REQUIRED)
    set(OPENSSL_LIBRARIES OpenSSL::Crypto)
endif()

# Jansson (Required dependency)
if(JANSSON_INCLUDE_DIR AND JANSSON_LIBRARIES)
    message(STATUS "CJOSE: Using manually provided Jansson paths.")
else()
    # Try finding via system or JANSSON_ROOT_DIR
    find_package(Jansson QUIET)
    if(NOT JANSSON_FOUND)
        find_path(JANSSON_INCLUDE_DIR NAMES jansson.h PATHS ${JANSSON_ROOT_DIR}/include)
        find_library(JANSSON_LIBRARIES NAMES jansson PATHS ${JANSSON_ROOT_DIR}/lib)
    endif()
endif()

if(NOT JANSSON_LIBRARIES OR NOT JANSSON_INCLUDE_DIR)
    message(FATAL_ERROR "Jansson not found. Use -DJANSSON_ROOT_DIR or provide full paths.")
endif()

# Check (Only if tests are enabled)
if(ENABLE_TESTS)
    find_package(Check 0.9.4 REQUIRED)
endif()

# --- System Checks (Autotools parity) ---
check_type_size(ssize_t SSIZE_T)
check_symbol_exists("random" stdlib.h HAVE_RANDOM)

# Check for openssl/fec.h as done in the original configure script
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
check_include_file("openssl/fec.h" HAVE_OPENSSL_FEC_H)

# --- Library Target Definition ---
file(GLOB CJOSE_SRC "${PROJECT_SOURCE_DIR}/src/*.c")
file(GLOB CJOSE_HDR_PUBLIC "${PROJECT_SOURCE_DIR}/include/cjose/*.h")
file(GLOB CJOSE_HDR_PRIVATE "${PROJECT_SOURCE_DIR}/src/include/*.h")

add_library(cjose ${CJOSE_SRC} ${CJOSE_HDR_PRIVATE} ${CJOSE_HDR_PUBLIC})

# Modern scope-based include directories
target_include_directories(cjose 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${OPENSSL_INCLUDE_DIR}
        ${JANSSON_INCLUDE_DIR}
)

target_link_libraries(cjose PRIVATE ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})

# Extra libraries for Unix environments
if(UNIX)
    find_library(M_LIB m)
    if(M_LIB)
        target_link_libraries(cjose PRIVATE ${M_LIB})
    endif()
endif()

# --- Compiler Flags and Definitions ---
if(MSVC)
    target_compile_options(cjose PRIVATE /W2 /WX /nologo /MP)
    target_compile_definitions(cjose PRIVATE VERSION="${PROJECT_VERSION}" _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(cjose PRIVATE -Wall -Werror --pedantic)
endif()

if(HAVE_OPENSSL_FEC_H)
    target_compile_definitions(cjose PRIVATE HAVE_OPENSSL_FEC_H=1)
endif()

if(ENABLE_RSA_PKCS1_5)
    target_compile_definitions(cjose PRIVATE HAVE_RSA_PKCS1_PADDING=1)
endif()

# --- Unit Tests ---
if(ENABLE_TESTS)
    file(GLOB CJOSE_TESTS_SRC "${PROJECT_SOURCE_DIR}/test/*.c")
    add_executable(cjose_tests ${CJOSE_TESTS_SRC})
    target_link_libraries(cjose_tests PRIVATE cjose ${CHECK_LIBRARIES} ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})
    enable_testing()
    add_test(NAME unit_tests COMMAND cjose_tests)
endif()

# --- Installation and Export ---
set_target_properties(cjose PROPERTIES PUBLIC_HEADER "${CJOSE_HDR_PUBLIC}")

install(TARGETS cjose
    EXPORT CjoseTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT lib
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT lib
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cjose COMPONENT dev
)

install(EXPORT CjoseTargets DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cjose COMPONENT dev)

# Generate and install pkg-config .pc file
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX})
set(libdir ${CMAKE_INSTALL_LIBDIR})
set(includedir ${CMAKE_INSTALL_INCLUDEDIR})
set(VERSION ${PROJECT_VERSION})

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cjose.pc.in" "${CMAKE_CURRENT_BINARY_DIR}/cjose.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cjose.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig COMPONENT dev)