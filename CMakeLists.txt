cmake_minimum_required(VERSION 3.16)
project(http-c C CXX)

# Prefer a modern C standard (adjust if your project requires another)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Prefer a modern C++ standard for test code
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Provide an INTERFACE 'http' target so CLion knows where headers live.
add_library(http INTERFACE)
# Project root contains http.h
target_include_directories(http INTERFACE ${CMAKE_SOURCE_DIR})

# Example executable that uses http.h
add_executable(example example.c)
target_link_libraries(example PRIVATE http)

# Optionally create a unit_tests target if tests/ contains .c files
file(GLOB TEST_SOURCES RELATIVE ${CMAKE_SOURCE_DIR} tests/*.c)
if(TEST_SOURCES)
  add_executable(unit_tests ${TEST_SOURCES})
  target_link_libraries(unit_tests PRIVATE http)
  target_include_directories(unit_tests PRIVATE ${CMAKE_SOURCE_DIR})
  # Register the C unit_tests executable with CTest so CLion can run it
  enable_testing()
  add_test(NAME unit_tests COMMAND unit_tests)
endif()

# --- doctest integration (C++ doctest framework) ---
# Try to download the single-header doctest.h into the build tree. If that
# fails (no network), fall back to a local vendor copy under
# ${CMAKE_SOURCE_DIR}/third_party/doctest/doctest.h if present. If neither is
# available, skip adding doctest tests and print an instruction to fetch it.
set(DOCTEST_VERSION v2.4.8)
set(DOCTEST_SINGLE_INCLUDE_URL "https://raw.githubusercontent.com/doctest/doctest/${DOCTEST_VERSION}/single_include/doctest/doctest.h")
# Desired layout: ${CMAKE_BINARY_DIR}/doctest/single_include/doctest/doctest.h
set(DOCTEST_BUILD_DIR "${CMAKE_BINARY_DIR}/doctest/single_include/doctest")
set(DOCTEST_BUILD_HEADER "${DOCTEST_BUILD_DIR}/doctest.h")
file(MAKE_DIRECTORY ${DOCTEST_BUILD_DIR})
file(DOWNLOAD ${DOCTEST_SINGLE_INCLUDE_URL} ${DOCTEST_BUILD_HEADER} SHOW_PROGRESS STATUS _dl_status)
list(GET _dl_status 0 _dl_code)

set(DOCTEST_FOUND OFF)
if(_dl_code EQUAL 0)
  # Download succeeded
  set(DOCTEST_FOUND ON)
  # Include parent of 'doctest' folder (i.e. ${CMAKE_BINARY_DIR}/doctest/single_include)
  get_filename_component(DOCTEST_INCLUDE_DIR ${DOCTEST_BUILD_DIR} DIRECTORY)
else()
  # Try local vendor copy at ${CMAKE_SOURCE_DIR}/third_party/doctest/doctest.h
  set(DOCTEST_VENDOR_HEADER "${CMAKE_SOURCE_DIR}/third_party/doctest/doctest.h")
  if(EXISTS ${DOCTEST_VENDOR_HEADER})
    # We need the include dir to be the parent of the 'doctest' folder, i.e.
    # ${CMAKE_SOURCE_DIR}/third_party so that <doctest/doctest.h> resolves.
    get_filename_component(DOCTEST_VENDOR_DIR ${DOCTEST_VENDOR_HEADER} DIRECTORY)
    get_filename_component(DOCTEST_INCLUDE_DIR ${DOCTEST_VENDOR_DIR} DIRECTORY)
    set(DOCTEST_FOUND ON)
    message(STATUS "Using local doctest header at ${DOCTEST_VENDOR_HEADER}")
  else()
    message(WARNING "Failed to download doctest single header from ${DOCTEST_SINGLE_INCLUDE_URL}.\n"
            "Doctest-based tests will be skipped. To enable them, fetch the header:\n"
            "  mkdir -p ${CMAKE_SOURCE_DIR}/third_party/doctest && \n  curl -L ${DOCTEST_SINGLE_INCLUDE_URL} -o ${CMAKE_SOURCE_DIR}/third_party/doctest/doctest.h\n")
  endif()
endif()

# Build the C implementation as a static library for linking into C++ tests
add_library(http_impl STATIC tests/http_impl.c)
target_link_libraries(http_impl PUBLIC http)
# Expose include directories for consumers (though http is already an INTERFACE)
target_include_directories(http_impl PUBLIC ${CMAKE_SOURCE_DIR})

# Add C++ doctest-based tests only if doctest is present
enable_testing()
if(DOCTEST_FOUND)
  add_executable(doctest_tests tests/doctest_example.cpp)
  add_executable(doctest_all tests/doctest_all.cpp tests/doctest_main.cpp)
  # Use a modern C++ standard for doctest
  set_target_properties(doctest_tests PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
  set_target_properties(doctest_all PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
  # Add doctest's header-only include directory
  target_include_directories(doctest_tests PRIVATE ${DOCTEST_INCLUDE_DIR})
  target_include_directories(doctest_all PRIVATE ${DOCTEST_INCLUDE_DIR})
  # Ensure C++ compilation uses the same feature-test macros as http.h
  target_compile_definitions(doctest_tests PRIVATE
    _POSIX_C_SOURCE=200809L
    _DEFAULT_SOURCE=1
    _BSD_SOURCE=1
    _GNU_SOURCE=1
    _DARWIN_C_SOURCE=1
  )
  target_compile_definitions(doctest_all PRIVATE
    _POSIX_C_SOURCE=200809L
    _DEFAULT_SOURCE=1
    _BSD_SOURCE=1
    _GNU_SOURCE=1
    _DARWIN_C_SOURCE=1
  )
  # Link with the C implementation and the http include interface
  target_link_libraries(doctest_tests PRIVATE http_impl http)
  target_link_libraries(doctest_all PRIVATE http_impl http)
  # Register the tests with CTest so CLion and ctest can run them
  add_test(NAME doctest_tests COMMAND doctest_tests)
  add_test(NAME doctest_all COMMAND doctest_all)
else()
  message(STATUS "Doctest header unavailable; skipping doctest_tests target.")
endif()
