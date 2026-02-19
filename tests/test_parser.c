#include "http.h"
#include "test_framework.h"

typedef struct {
  int on_request_line_called;
  int on_headers_complete_called;
  int on_body_called;
  int on_complete_called;
} test_data_t;

static void on_request_line(void *user_data, http_method_t method,
                            const char *uri, const char *version) {
  (void)method;
  (void)uri;
  (void)version;
  test_data_t *td = (test_data_t *)user_data;
  td->on_request_line_called++;
}

static void on_headers_complete(void *user_data) {
  test_data_t *td = (test_data_t *)user_data;
  td->on_headers_complete_called++;
}

static void on_body(void *user_data, const char *data, size_t len) {
  (void)data;
  (void)len;
  test_data_t *td = (test_data_t *)user_data;
  td->on_body_called++;
}

static void on_complete(void *user_data) {
  test_data_t *td = (test_data_t *)user_data;
  td->on_complete_called++;
}

TEST_CASE(test_basic_get_request) {
  http_parser_t parser;
  test_data_t td = {0, 0, 0, 0};
  http_parser_settings_t settings = {on_request_line,
                                     NULL, // on_header
                                     on_body, on_headers_complete, on_complete};

  http_parser_init(&parser);
  parser.user_data = &td;
  const char *req = "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
  size_t n = http_parser_execute(&parser, &settings, req, strlen(req));

  CHECK_EQ(n, strlen(req));
  CHECK_EQ(td.on_request_line_called, 1);
  CHECK_EQ(td.on_headers_complete_called, 1);
  CHECK_EQ(td.on_complete_called, 1);
  CHECK(http_parser_is_done(&parser));
}

TEST_CASE(test_chunked_request_parsing) {
  http_parser_t parser;
  test_data_t td = {0, 0, 0, 0};
  http_parser_settings_t settings = {on_request_line, NULL, on_body,
                                     on_headers_complete, on_complete};

  http_parser_init(&parser);
  parser.user_data = &td;
  const char *req1 = "GET /hel";
  const char *req2 = "lo HTTP/1.1\r\n\r\n";

  http_parser_execute(&parser, &settings, req1, strlen(req1));
  CHECK_EQ(td.on_request_line_called, 0);

  http_parser_execute(&parser, &settings, req2, strlen(req2));
  CHECK_EQ(td.on_request_line_called, 1);
  CHECK_EQ(td.on_complete_called, 1);
}

TEST_CASE(test_post_request_with_body) {
  http_parser_t parser;
  test_data_t td = {0, 0, 0, 0};
  http_parser_settings_t settings = {on_request_line, NULL, on_body,
                                     on_headers_complete, on_complete};

  http_parser_init(&parser);
  parser.user_data = &td;
  const char *post_req =
      "POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
  http_parser_execute(&parser, &settings, post_req, strlen(post_req));

  CHECK_EQ(td.on_body_called, 5);
  CHECK_EQ(td.on_complete_called, 1);
}

// New tests added below
TEST_CASE(test_incremental_byte_by_byte_parsing) {
  http_parser_t parser;
  test_data_t td = {0, 0, 0, 0};
  http_parser_settings_t settings = {on_request_line, NULL, on_body,
                                     on_headers_complete, on_complete};
  const char *req = "GET /incr HTTP/1.1\r\nHost: x\r\n\r\n";

  http_parser_init(&parser);
  parser.user_data = &td;

  // Feed one byte at a time to simulate very small recv buffers
  for (size_t i = 0; i < strlen(req); i++) {
    size_t n = http_parser_execute(&parser, &settings, req + i, 1);
    // Expect parser to consume at least 0 or 1 bytes; ensure it never consumes
    // more than provided.
    CHECK(n <= 1);
  }

  CHECK_EQ(td.on_request_line_called, 1);
  CHECK_EQ(td.on_headers_complete_called, 1);
  CHECK_EQ(td.on_complete_called, 1);
  CHECK(http_parser_is_done(&parser));
}

TEST_CASE(test_header_line_overflow_detected) {
  http_parser_t parser;
  test_data_t td = {0, 0, 0, 0};
  http_parser_settings_t settings = {on_request_line, NULL, on_body,
                                     on_headers_complete, on_complete};

  http_parser_init(&parser);
  parser.user_data = &td;

  // Build a request with an overly long single header line
  size_t overflow_len = MAX_HEADER_LINE_LEN + 100;
  char *req = (char *)malloc(overflow_len + 128);
  strcpy(req, "GET /big HTTP/1.1\r\n");
  strcat(req, "X-Long-Header: ");
  size_t prefix_len = strlen(req);
  // fill to overflow
  for (size_t i = 0; i < overflow_len; i++)
    req[prefix_len + i] = 'A';
  req[prefix_len + overflow_len] = '\0';
  strcat(req, "\r\n\r\n");

  size_t total_len = strlen(req);
  size_t consumed = http_parser_execute(&parser, &settings, req, total_len);

  // Parser should stop processing at the point it detects the overflow and
  // should not call on_headers_complete or on_complete.
  CHECK(td.on_headers_complete_called == 0);
  CHECK(td.on_complete_called == 0);
  CHECK(consumed < total_len);

  free(req);
}
