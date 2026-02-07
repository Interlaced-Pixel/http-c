#include "http.h"
#include "test_framework.h"

TEST_CASE(test_str_trim) {
  char s1[] = "  hello  ";
  str_trim(s1);
  CHECK_STR_EQ(s1, "hello");

  char s2[] = "world";
  str_trim(s2);
  CHECK_STR_EQ(s2, "world");

  char s3[] = "   ";
  str_trim(s3);
  CHECK_STR_EQ(s3, "");
}

TEST_CASE(test_path_normalize) {
  char dst[1024];

  path_normalize(dst, "/foo/bar/../baz", sizeof(dst));
  CHECK_STR_EQ(dst, "/foo/baz");

  path_normalize(dst, "/foo/./bar", sizeof(dst));
  CHECK_STR_EQ(dst, "/foo/bar");

  path_normalize(dst, "/../../etc/passwd", sizeof(dst));
  CHECK_STR_EQ(dst, "/etc/passwd");

  path_normalize(dst, "////foo//bar/", sizeof(dst));
  // Note: trailing slash stripped by strtok implementation
  CHECK_STR_EQ(dst, "/foo/bar");
}

TEST_CASE(test_url_decode) {
  char dst[1024];
  url_decode(dst, "hello%20world", sizeof(dst));
  CHECK_STR_EQ(dst, "hello world");
  url_decode(dst, "foo+bar", sizeof(dst));
  CHECK_STR_EQ(dst, "foo bar");
}

TEST_CASE(test_path_is_safe) {
  CHECK(path_is_safe("foo/bar.txt"));
  CHECK(!path_is_safe("/etc/passwd"));
  CHECK(!path_is_safe("foo/../bar"));
  CHECK(!path_is_safe("C:/Windows"));
}

TEST_CASE(test_mime_type_from_path) {
  CHECK_STR_EQ(mime_type_from_path("index.html"), "text/html");
  CHECK_STR_EQ(mime_type_from_path("styles.css"), "text/css");
  CHECK_STR_EQ(mime_type_from_path("script.js"), "application/javascript");
  CHECK_STR_EQ(mime_type_from_path("data.json"), "application/json");
  CHECK_STR_EQ(mime_type_from_path("file.unknown"), "application/octet-stream");
}

TEST_CASE(test_http_date) {
  struct tm tm = {0};
  tm.tm_year = 1994 - 1900;
  tm.tm_mon = 10; // Nov
  tm.tm_mday = 6;
  tm.tm_hour = 8;
  tm.tm_min = 49;
  tm.tm_sec = 37;
#if PLATFORM_WINDOWS
  time_t t = _mkgmtime(&tm);
#else
  time_t t = timegm(&tm);
#endif
  char buf[64];
  CHECK_EQ(http_format_date(buf, sizeof(buf), t), 0);
  CHECK_STR_EQ(buf, "Sun, 06 Nov 1994 08:49:37 GMT");
  time_t parsed = http_parse_date(buf);
  CHECK(parsed != (time_t)-1);
  CHECK_EQ(parsed, t);
}

TEST_CASE(test_http_method_conversion) {
  CHECK_EQ(http_method_from_string("GET"), HTTP_METHOD_GET);
  CHECK_EQ(http_method_from_string("POST"), HTTP_METHOD_POST);
  CHECK_EQ(http_method_from_string("UNKNOWN"), HTTP_METHOD_UNKNOWN);
  CHECK_STR_EQ(http_method_to_string(HTTP_METHOD_GET), "GET");
  CHECK_STR_EQ(http_method_to_string(HTTP_METHOD_POST), "POST");
}
