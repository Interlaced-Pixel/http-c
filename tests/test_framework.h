#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int tests_run;
extern int tests_failed;

#define TEST_ASSERT(cond, msg)                                                 \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("FAILED: %s:%d: %s\n", __FILE__, __LINE__, msg);                  \
      tests_failed++;                                                          \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define CHECK(cond) TEST_ASSERT(cond, #cond)

#define CHECK_EQ(a, b)                                                         \
  do {                                                                         \
    long long _a = (long long)(a);                                             \
    long long _b = (long long)(b);                                             \
    if (_a != _b) {                                                            \
      printf("FAILED: %s:%d: %s != %s (%lld != %lld)\n", __FILE__, __LINE__,   \
             #a, #b, _a, _b);                                                  \
      tests_failed++;                                                          \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define CHECK_STR_EQ(a, b)                                                     \
  do {                                                                         \
    const char *_a = (const char *)(a);                                        \
    const char *_b = (const char *)(b);                                        \
    if (strcmp(_a, _b) != 0) {                                                 \
      printf("FAILED: %s:%d: %s != %s (\"%s\" != \"%s\")\n", __FILE__,         \
             __LINE__, #a, #b, _a, _b);                                        \
      tests_failed++;                                                          \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define TEST_CASE(name) void name(void)

#define RUN_TEST(func)                                                         \
  do {                                                                         \
    int failed_before = tests_failed;                                          \
    printf("Running %s...\n", #func);                                          \
    func();                                                                    \
    tests_run++;                                                               \
    if (tests_failed == failed_before) {                                       \
      printf("PASS: %s\n", #func);                                             \
    }                                                                          \
  } while (0)

#define PRINT_TEST_RESULTS()                                                   \
  do {                                                                         \
    printf("\nTest Results: %d run, %d failed\n", tests_run, tests_failed);    \
    if (tests_failed > 0)                                                      \
      exit(1);                                                                 \
  } while (0)

#endif // TEST_FRAMEWORK_H
