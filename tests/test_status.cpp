#include "doctest.h"
#include <string>

extern "C" {
#include "http.h"
}

TEST_SUITE("Status") {
  TEST_CASE("known status reasons") {
    CHECK_EQ(std::string(http_status_reason(200)), "OK");
    CHECK_EQ(std::string(http_status_reason(404)), "Not Found");
    CHECK_EQ(std::string(http_status_reason(500)), "Internal Server Error");
    CHECK_EQ(std::string(http_status_reason(301)), "Moved Permanently");
  }

  TEST_CASE("default class reason") {
    CHECK_EQ(std::string(http_status_reason(450)), "Client Error");
    CHECK_EQ(std::string(http_status_reason(299)), "Success");
    CHECK_EQ(std::string(http_status_reason(700)), "Unknown");
  }
}
