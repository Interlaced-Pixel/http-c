#include <doctest/doctest.h>

// Provide a main that invokes the doctest_mini runner from the vendored header.
int main(int argc, char** argv) {
  (void)argc; (void)argv;
  return doctest_mini::run_all_tests();
}

