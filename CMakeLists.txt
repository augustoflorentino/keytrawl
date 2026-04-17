cmake_minimum_required(VERSION 3.16)
project(keytrawl VERSION 0.2.0 DESCRIPTION "Streaming secret finder for raw bytes: private keys, cloud tokens and configuration secrets, each validated before it is reported" LANGUAGES C)

option(KEYTRAWL_BUILD_TESTS "Build tests" OFF)
option(KEYTRAWL_BUILD_EXAMPLES "Build examples" OFF)
option(KEYTRAWL_BUILD_FUZZ "Build libFuzzer targets" OFF)
option(KEYTRAWL_BUILD_BENCH "Build the benchmark (POSIX threads)" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_library(keytrawl
    src/ktw_catalog.c
    src/ktw_scanner.c
    src/ktw_pem.c
    src/ktw_der.c
    src/ktw_ssh.c
    src/ktw_token.c
    src/ktw_config.c
    src/ktw_hash.c
    src/ktw_derive.c
    src/ktw_pair.c)
add_library(keytrawl::keytrawl ALIAS keytrawl)
target_include_directories(keytrawl PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_target_properties(keytrawl PROPERTIES
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

set(PC_CFLAGS "")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(keytrawl PRIVATE KTW_BUILD_SHARED INTERFACE KTW_SHARED)
    set(PC_CFLAGS "-DKTW_SHARED")
endif()

install(TARGETS keytrawl EXPORT keytrawlTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT keytrawlTargets
    NAMESPACE keytrawl::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/keytrawl)

configure_package_config_file(cmake/keytrawlConfig.cmake.in
    ${PROJECT_BINARY_DIR}/keytrawlConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/keytrawl)
write_basic_package_version_file(${PROJECT_BINARY_DIR}/keytrawlConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${PROJECT_BINARY_DIR}/keytrawlConfig.cmake
    ${PROJECT_BINARY_DIR}/keytrawlConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/keytrawl)

configure_file(keytrawl.pc.in ${PROJECT_BINARY_DIR}/keytrawl.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/keytrawl.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(KEYTRAWL_BUILD_TESTS)
    enable_testing()
    add_executable(test_keytrawl tests/test_keytrawl.c)
    target_link_libraries(test_keytrawl PRIVATE keytrawl)
    target_compile_definitions(test_keytrawl PRIVATE KTW_TEST_DATA="${PROJECT_SOURCE_DIR}/tests/data")
    add_test(NAME keytrawl COMMAND test_keytrawl)
    add_library(keytrawl_header_check OBJECT tests/header_check.c)
    target_include_directories(keytrawl_header_check PRIVATE include)
endif()

if(KEYTRAWL_BUILD_EXAMPLES)
    add_executable(keytrawl_basic examples/basic.c)
    target_link_libraries(keytrawl_basic PRIVATE keytrawl)
    add_executable(keytrawl_cli examples/keytrawl.c)
    target_link_libraries(keytrawl_cli PRIVATE keytrawl)
    set_target_properties(keytrawl_cli PROPERTIES OUTPUT_NAME keytrawl)
endif()

if(KEYTRAWL_BUILD_FUZZ)
    add_executable(fuzz_scan fuzz/fuzz_scan.c)
    target_link_libraries(fuzz_scan PRIVATE keytrawl)
    target_link_options(fuzz_scan PRIVATE -fsanitize=fuzzer)
endif()

if(KEYTRAWL_BUILD_BENCH)
    find_package(Threads REQUIRED)
    add_executable(keytrawl_bench bench/bench.c)
    target_link_libraries(keytrawl_bench PRIVATE keytrawl Threads::Threads)
endif()
