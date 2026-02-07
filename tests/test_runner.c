#include "test_framework.h"

// External test cases
extern void test_str_trim(void);
extern void test_path_normalize(void);
extern void test_url_decode(void);
extern void test_path_is_safe(void);
extern void test_mime_type_from_path(void);
extern void test_http_date(void);
extern void test_http_method_conversion(void);

extern void test_status_reasons(void);
extern void test_default_class_reason(void);

extern void test_mem_pool_allocation(void);

extern void test_basic_get_request(void);
extern void test_chunked_request_parsing(void);
extern void test_post_request_with_body(void);

extern void test_server_integration(void);

int main(void) {
  // Utils
  RUN_TEST(test_str_trim);
  RUN_TEST(test_path_normalize);
  RUN_TEST(test_url_decode);
  RUN_TEST(test_path_is_safe);
  RUN_TEST(test_mime_type_from_path);
  RUN_TEST(test_http_date);
  RUN_TEST(test_http_method_conversion);

  // Status
  RUN_TEST(test_status_reasons);
  RUN_TEST(test_default_class_reason);

  // Mem pool
  RUN_TEST(test_mem_pool_allocation);

  // Parser
  RUN_TEST(test_basic_get_request);
  RUN_TEST(test_chunked_request_parsing);
  RUN_TEST(test_post_request_with_body);

  // Server
  RUN_TEST(test_server_integration);

  PRINT_TEST_RESULTS();
  return 0;
}
