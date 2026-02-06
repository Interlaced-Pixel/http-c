# Compiler and flags
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -std=c99 -O2 -I.
CXXFLAGS = -Wall -Wextra -std=c++11 -g -O0 -I. -Itests
LDFLAGS = 

# Coverage flags
COVERAGE_FLAGS = --coverage

# Build directory
BUILD_DIR = build

# Targets
all: $(BUILD_DIR)/example

$(BUILD_DIR)/example: $(BUILD_DIR)/example.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/example.o: example.c http.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Test target using doctest (C++)
TEST_SRCS = tests/test_runner.cpp tests/test_utils.cpp tests/test_status.cpp tests/test_mem_pool.cpp tests/test_parser.cpp tests/test_server.cpp
HTTP_IMPL_OBJ = $(BUILD_DIR)/http_impl.o

$(BUILD_DIR)/unit_tests: $(TEST_SRCS) $(HTTP_IMPL_OBJ) http.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(COVERAGE_FLAGS) -o $@ $(TEST_SRCS) $(HTTP_IMPL_OBJ) $(LDFLAGS)

$(BUILD_DIR)/http_impl.o: tests/http_impl.c http.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_FLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

test: $(BUILD_DIR)/unit_tests
	./$(BUILD_DIR)/unit_tests

coverage: $(BUILD_DIR)/unit_tests
	./$(BUILD_DIR)/unit_tests
	gcov -abcfu -o $(BUILD_DIR) tests/http_impl.c
	mv *.gcov $(BUILD_DIR)/
	@echo "\n--- Coverage Summary ---"
	@grep "File 'http.h'" -A 1 $(BUILD_DIR)/http.h.gcov || true

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all test clean coverage