#include <doctest/doctest.h>

extern "C" {
#include "http.h"
}

#include <cstring>
#include <ctime>
#include <string>

TEST_CASE("utils: str_trim") {
  char s1[] = "  hello  ";
  str_trim(s1);
  CHECK(std::strcmp(s1, "hello") == 0);

  char s2[] = "world";
  str_trim(s2);
  CHECK(std::strcmp(s2, "world") == 0);

  char s3[] = "   ";
  str_trim(s3);
  CHECK(std::strcmp(s3, "") == 0);
}

TEST_CASE("utils: path_normalize") {
  char dst[1024];
  path_normalize(dst, "/foo/bar/../baz", sizeof(dst));
  CHECK(std::strcmp(dst, "/foo/baz") == 0);
  path_normalize(dst, "/foo/./bar", sizeof(dst));
  CHECK(std::strcmp(dst, "/foo/bar") == 0);
  path_normalize(dst, "/../../etc/passwd", sizeof(dst));
  CHECK(std::strcmp(dst, "/etc/passwd") == 0);
  path_normalize(dst, "////foo//bar/", sizeof(dst));
  CHECK(std::strcmp(dst, "/foo/bar") == 0);
}

TEST_CASE("utils: url_decode") {
  char dst[1024];
  url_decode(dst, "hello%20world", sizeof(dst));
  CHECK(std::strcmp(dst, "hello world") == 0);
  url_decode(dst, "foo+bar", sizeof(dst));
  CHECK(std::strcmp(dst, "foo bar") == 0);
}

TEST_CASE("utils: path_is_safe") {
  CHECK(path_is_safe("foo/bar.txt"));
  CHECK(!path_is_safe("/etc/passwd"));
  CHECK(!path_is_safe("foo/../bar"));
  CHECK(!path_is_safe("C:/Windows"));
}

TEST_CASE("utils: mime_type_from_path") {
  CHECK(std::strcmp(mime_type_from_path("index.html"), "text/html") == 0);
  CHECK(std::strcmp(mime_type_from_path("styles.css"), "text/css") == 0);
  CHECK(std::strcmp(mime_type_from_path("script.js"), "application/javascript") == 0);
  CHECK(std::strcmp(mime_type_from_path("data.json"), "application/json") == 0);
  CHECK(std::strcmp(mime_type_from_path("file.unknown"), "application/octet-stream") == 0);
}

TEST_CASE("utils: http_date roundtrip") {
  struct tm tm = {0};
  tm.tm_year = 1994 - 1900;
  tm.tm_mon = 10;
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
  CHECK(std::strcmp(buf, "Sun, 06 Nov 1994 08:49:37 GMT") == 0);
  time_t parsed = http_parse_date(buf);
  CHECK(parsed != (time_t)-1);
  CHECK_EQ(parsed, t);
}

TEST_CASE("utils: http_method conversion") {
  CHECK_EQ(http_method_from_string("GET"), HTTP_METHOD_GET);
  CHECK_EQ(http_method_from_string("POST"), HTTP_METHOD_POST);
  CHECK_EQ(http_method_from_string("UNKNOWN"), HTTP_METHOD_UNKNOWN);
  CHECK(std::strcmp(http_method_to_string(HTTP_METHOD_GET), "GET") == 0);
}

TEST_CASE("mem_pool allocation") {
  mem_pool_t pool;
  mem_pool_init(&pool, 1024);
  void *p1 = mem_pool_alloc(&pool);
  CHECK(p1 != nullptr);
  void *p2 = mem_pool_alloc(&pool);
  CHECK(p2 != nullptr);
  CHECK(p1 != p2);
  mem_pool_free(&pool, p1);
  void *p3 = mem_pool_alloc(&pool);
  CHECK(p3 == p1);
  mem_pool_free(&pool, p2);
  mem_pool_free(&pool, p3);
}

TEST_CASE("parser: basic get request") {
  http_parser_t parser;
  typedef struct { int on_request_line_called; int on_headers_complete_called; int on_body_called; int on_complete_called; } test_data_t;
  test_data_t td = {0,0,0,0};
  auto on_request_line = [](void *user_data, http_method_t method, const char *uri, const char *version) {
    (void)method; (void)uri; (void)version; auto td = (test_data_t*)user_data; td->on_request_line_called++;
  };
  auto on_headers_complete = [](void *user_data) { auto td = (test_data_t*)user_data; td->on_headers_complete_called++; };
  auto on_body = [](void *user_data, const char *data, size_t len) { (void)data; (void)len; auto td = (test_data_t*)user_data; td->on_body_called++; };
  auto on_complete = [](void *user_data) { auto td = (test_data_t*)user_data; td->on_complete_called++; };
  http_parser_settings_t settings = { (on_request_line_cb) +0, NULL, (on_body_cb) +0, (on_headers_complete_cb) +0, (on_complete_cb) +0 };
  // Build settings by assigning function pointers to static functions with C linkage
  // Because taking the address of a lambda isn't trivial for C function pointer, we'll define static C-style functions instead below.
}

// To satisfy the parser callbacks with C function pointers we define static C functions and a struct to hold counters.
extern "C" {
static int _td_on_request_line_called = 0;
static int _td_on_headers_complete_called = 0;
static int _td_on_body_called = 0;
static int _td_on_complete_called = 0;

static void _td_on_request_line(void *user_data, http_method_t method, const char *uri, const char *version) {
  (void)user_data; (void)method; (void)uri; (void)version; _td_on_request_line_called++;
}
static void _td_on_headers_complete(void *user_data) { (void)user_data; _td_on_headers_complete_called++; }
static void _td_on_body(void *user_data, const char *data, size_t len) { (void)user_data; (void)data; (void)len; _td_on_body_called++; }
static void _td_on_complete(void *user_data) { (void)user_data; _td_on_complete_called++; }
}

TEST_CASE("parser: basic get request (impl)") {
  http_parser_t parser;
  _td_on_request_line_called = _td_on_headers_complete_called = _td_on_body_called = _td_on_complete_called = 0;
  http_parser_settings_t settings = {_td_on_request_line, NULL, _td_on_body, _td_on_headers_complete, _td_on_complete};
  http_parser_init(&parser);
  const char *req = "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
  size_t n = http_parser_execute(&parser, &settings, req, strlen(req));
  CHECK_EQ(n, strlen(req));
  CHECK_EQ(_td_on_request_line_called, 1);
  CHECK_EQ(_td_on_headers_complete_called, 1);
  CHECK_EQ(_td_on_complete_called, 1);
  CHECK(http_parser_is_done(&parser));
}

TEST_CASE("parser: chunked request parsing") {
  http_parser_t parser;
  _td_on_request_line_called = _td_on_headers_complete_called = _td_on_body_called = _td_on_complete_called = 0;
  http_parser_settings_t settings = {_td_on_request_line, NULL, _td_on_body, _td_on_headers_complete, _td_on_complete};
  http_parser_init(&parser);
  const char *req1 = "GET /hel";
  const char *req2 = "lo HTTP/1.1\r\n\r\n";
  http_parser_execute(&parser, &settings, req1, strlen(req1));
  CHECK_EQ(_td_on_request_line_called, 0);
  http_parser_execute(&parser, &settings, req2, strlen(req2));
  CHECK_EQ(_td_on_request_line_called, 1);
  CHECK_EQ(_td_on_complete_called, 1);
}

TEST_CASE("parser: post request with body") {
  http_parser_t parser;
  _td_on_request_line_called = _td_on_headers_complete_called = _td_on_body_called = _td_on_complete_called = 0;
  http_parser_settings_t settings = {_td_on_request_line, NULL, _td_on_body, _td_on_headers_complete, _td_on_complete};
  http_parser_init(&parser);
  const char *post_req = "POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
  http_parser_execute(&parser, &settings, post_req, strlen(post_req));
  CHECK_EQ(_td_on_body_called, 5);
  CHECK_EQ(_td_on_complete_called, 1);
}

TEST_CASE("parser: incremental byte-by-byte parsing") {
  http_parser_t parser;
  _td_on_request_line_called = _td_on_headers_complete_called = _td_on_body_called = _td_on_complete_called = 0;
  http_parser_settings_t settings = {_td_on_request_line, NULL, _td_on_body, _td_on_headers_complete, _td_on_complete};
  const char *req = "GET /incr HTTP/1.1\r\nHost: x\r\n\r\n";
  http_parser_init(&parser);
  for (size_t i = 0; i < strlen(req); i++) {
    size_t n = http_parser_execute(&parser, &settings, req + i, 1);
    CHECK(n <= 1);
  }
  CHECK_EQ(_td_on_request_line_called, 1);
  CHECK_EQ(_td_on_headers_complete_called, 1);
  CHECK_EQ(_td_on_complete_called, 1);
}

TEST_CASE("parser: header line overflow detected") {
  http_parser_t parser;
  _td_on_request_line_called = _td_on_headers_complete_called = _td_on_body_called = _td_on_complete_called = 0;
  http_parser_settings_t settings = {_td_on_request_line, NULL, _td_on_body, _td_on_headers_complete, _td_on_complete};
  http_parser_init(&parser);
  size_t overflow_len = MAX_HEADER_LINE_LEN + 100;
  char *req = (char *)malloc(overflow_len + 128);
  strcpy(req, "GET /big HTTP/1.1\r\n");
  strcat(req, "X-Long-Header: ");
  size_t prefix_len = strlen(req);
  for (size_t i = 0; i < overflow_len; i++) req[prefix_len + i] = 'A';
  req[prefix_len + overflow_len] = '\0';
  strcat(req, "\r\n\r\n");
  size_t total_len = strlen(req);
  size_t consumed = http_parser_execute(&parser, &settings, req, total_len);
  CHECK(_td_on_headers_complete_called == 0);
  CHECK(_td_on_complete_called == 0);
  CHECK(consumed < total_len);
  free(req);
}

TEST_CASE("status: reasons and default class") {
  CHECK(std::strcmp(http_status_reason(200), "OK") == 0);
  CHECK(std::strcmp(http_status_reason(404), "Not Found") == 0);
  CHECK(std::strcmp(http_status_reason(500), "Internal Server Error") == 0);
  CHECK(std::strcmp(http_status_reason(301), "Moved Permanently") == 0);
  CHECK(std::strcmp(http_status_reason(450), "Client Error") == 0);
  CHECK(std::strcmp(http_status_reason(299), "Success") == 0);
  CHECK(std::strcmp(http_status_reason(700), "Unknown") == 0);
}

TEST_CASE("server integration (light)") {
  // This mirrors some of test_server.c but avoids creating many sockets to
  // reduce flakiness in CI. It performs a few file operations and checks
  // HTTP helpers.
  char *dup = strdup_safe("test");
  CHECK(std::strcmp(dup, "test") == 0);
  free(dup);
  mem_pool_t pool; mem_pool_init(&pool, 5);
  void *p1 = mem_pool_alloc(&pool);
  CHECK(p1 != NULL);
  mem_pool_free(&pool, p1);

  CHECK_EQ(http_method_from_string("PATCH"), HTTP_METHOD_PATCH);
  CHECK(std::strcmp(http_method_to_string(HTTP_METHOD_PATCH), "PATCH") == 0);

  file_content_t fc;
  FILE *ft = fopen("t.txt", "w"); fputc('x', ft); fclose(ft);
  CHECK_EQ(file_read("t.txt", &fc), 0);
  file_free(&fc);
  unlink("t.txt");

  // HEAD method and file send tests are environment-dependent (sockets),
  // but we invoke some http_conn_xxx functions to ensure API surface compiles
  http_conn_t conn; http_conn_init(&conn);
  http_conn_close(&conn);
}
