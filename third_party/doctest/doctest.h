#ifndef DOCTEST_MINI_H
#define DOCTEST_MINI_H

/* Minimal doctest-compatible header (small subset) for this project.
   Provides TEST_CASE, CHECK, CHECK_EQ, CHECK_STR_EQ and simple test registration.
   This is intentionally small and not the full doctest library.
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

#ifdef DOCTEST_CONFIG_IMPLEMENT_WITHOUT_MAIN
#define DOCTEST_MINI_NO_MAIN
#endif

namespace doctest_mini {
  typedef void (*test_func_t)();
  struct TestCase { const char* name; test_func_t func; };
  inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
  }
  inline int& tests_run() { static int v = 0; return v; }
  inline int& tests_failed() { static int v = 0; return v; }
  inline void register_test(const char* name, test_func_t f) {
    registry().push_back({name, f});
  }
  inline void print_result_and_maybe_exit() {
    std::printf("\nTest Results: %d run, %d failed\n", tests_run(), tests_failed());
    if (tests_failed() > 0) std::exit(1);
  }
}

#define DOCTEST_CONCAT_IMPL(x,y) x##y
#define DOCTEST_CONCAT(x,y) DOCTEST_CONCAT_IMPL(x,y)

#define TEST_CASE(name) \
  static void DOCTEST_CONCAT(doctest_func_, __LINE__)(); \
  namespace { struct DOCTEST_CONCAT(doctest_reg_, __LINE__) { DOCTEST_CONCAT(doctest_reg_, __LINE__)() { doctest_mini::register_test(name, &DOCTEST_CONCAT(doctest_func_, __LINE__)); } } DOCTEST_CONCAT(doctest_reg_instance_, __LINE__); } \
  static void DOCTEST_CONCAT(doctest_func_, __LINE__)()

#define TEST_CASE_FIXTURE(name) TEST_CASE(name)

// Provide runner function (no main). Tests should provide main that calls
// doctest_mini::run_all_tests().
namespace doctest_mini {
  inline int run_all_tests() {
    for (auto &t : registry()) {
      std::printf("Running %s...\n", t.name);
      int failed_before = tests_failed();
      t.func();
      tests_run()++;
      if (tests_failed() == failed_before) {
        std::printf("PASS: %s\n", t.name);
      }
    }
    print_result_and_maybe_exit();
    return 0;
  }
}

// Assertion helpers (simple, mirror project's test_framework semantics)
#define DOCTEST_CHECK_IMPL(cond, file, line, expr) do { \
  if (!(cond)) { \
    std::fprintf(stderr, "FAILED: %s:%d: %s\n", file, line, expr); \
    doctest_mini::tests_failed()++; \
    return; \
  } \
} while(0)

#define CHECK(expr) DOCTEST_CHECK_IMPL((expr), __FILE__, __LINE__, #expr)

#define CHECK_EQ(a, b) do { \
  long long _a = (long long)(a); long long _b = (long long)(b); \
  if (_a != _b) { \
    std::fprintf(stderr, "FAILED: %s:%d: %s != %s (%lld != %lld)\n", __FILE__, __LINE__, #a, #b, _a, _b); \
    doctest_mini::tests_failed()++; \
    return; \
  } \
} while(0)

#define CHECK_STR_EQ(a, b) do { \
  const char* _a = (const char*)(a); const char* _b = (const char*)(b); \
  if (std::strcmp(_a, _b) != 0) { \
    std::fprintf(stderr, "FAILED: %s:%d: %s != %s (\"%s\" != \"%s\")\n", __FILE__, __LINE__, #a, #b, _a, _b); \
    doctest_mini::tests_failed()++; \
    return; \
  } \
} while(0)

#endif // DOCTEST_MINI_H

