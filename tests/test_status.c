#include "http.h"
#include "test_framework.h"

TEST_CASE(test_status_reasons) {
  CHECK_STR_EQ(http_status_reason(200), "OK");
  CHECK_STR_EQ(http_status_reason(404), "Not Found");
  CHECK_STR_EQ(http_status_reason(500), "Internal Server Error");
  CHECK_STR_EQ(http_status_reason(301), "Moved Permanently");
}

TEST_CASE(test_default_class_reason) {
  CHECK_STR_EQ(http_status_reason(450), "Client Error");
  CHECK_STR_EQ(http_status_reason(299), "Success");
  CHECK_STR_EQ(http_status_reason(700), "Unknown");
}
