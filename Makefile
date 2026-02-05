# Compiler and flags
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -std=c99 -O2 -I.
CXXFLAGS = -Wall -Wextra -std=c++11 -g -O0 -I. -Itests
LDFLAGS = 

# Coverage flags
COVERAGE_FLAGS = --coverage

# Targets
all: example

example: example.o
	$(CC) $(CFLAGS) -o example example.o $(LDFLAGS)

example.o: example.c http.h
	$(CC) $(CFLAGS) -c example.c

# Test target using doctest (C++)
TEST_SRCS = tests/test_runner.cpp tests/test_utils.cpp tests/test_mem_pool.cpp tests/test_parser.cpp tests/test_server.cpp
HTTP_IMPL_OBJ = tests/http_impl.o

unit_tests: $(TEST_SRCS) $(HTTP_IMPL_OBJ) http.h
	$(CXX) $(CXXFLAGS) $(COVERAGE_FLAGS) -o unit_tests $(TEST_SRCS) $(HTTP_IMPL_OBJ) $(LDFLAGS)

tests/http_impl.o: tests/http_impl.c http.h
	$(CC) $(CFLAGS) $(COVERAGE_FLAGS) -c tests/http_impl.c -o tests/http_impl.o

test: unit_tests
	./unit_tests

coverage: unit_tests
	./unit_tests
	cd tests && gcov -abcfu http_impl.c && mv *.gcov ..
	@echo "\n--- Coverage Summary ---"
	@grep "File 'http.h'" -A 1 http.h.gcov || true

clean:
	rm -rf example.o example unit_tests *.gcno *.gcda *.gcov tests/*.gcno tests/*.gcda tests/*.gcov *.dSYM

.PHONY: all test clean coverage