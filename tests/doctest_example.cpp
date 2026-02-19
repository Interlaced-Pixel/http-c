#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

extern "C" {
#include "http.h"
}

TEST_CASE("strdup_safe returns NULL for NULL and duplicates string") {
  const char *s = "hello";
  char *d = strdup_safe(s);
  CHECK(d != nullptr);
  CHECK(std::strcmp(d, s) == 0);
  free(d);

  char *n = strdup_safe(nullptr);
  CHECK(n == nullptr);
}

TEST_CASE("str_trim trims whitespace") {
  char s[] = "   abc  \t\n";
  str_trim(s);
  CHECK(std::strcmp(s, "abc") == 0);
}

TEST_CASE("http_method conversion roundtrip") {
  CHECK(http_method_from_string("GET") == HTTP_METHOD_GET);
  CHECK(std::strcmp(http_method_to_string(HTTP_METHOD_GET), "GET") == 0);
}

