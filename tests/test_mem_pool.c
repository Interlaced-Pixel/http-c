#include "http.h"
#include "test_framework.h"

TEST_CASE(test_mem_pool_allocation) {
  mem_pool_t pool;
  mem_pool_init(&pool, 1024);

  // Allocate something
  void *p1 = mem_pool_alloc(&pool);
  CHECK(p1 != NULL);

  // Allocate more
  void *p2 = mem_pool_alloc(&pool);
  CHECK(p2 != NULL);
  CHECK(p1 != p2);

  // Free and reallocate
  mem_pool_free(&pool, p1);
  void *p3 = mem_pool_alloc(&pool);
  CHECK(p3 == p1); // Should reuse p1

  mem_pool_free(&pool, p2);
  mem_pool_free(&pool, p3);
}
