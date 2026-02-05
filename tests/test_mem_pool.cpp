#include "doctest.h"
extern "C" {
#include "http.h"
}

TEST_SUITE("MemPool") {
  TEST_CASE("allocation and reuse") {
    mem_pool_t pool;
    mem_pool_init(&pool, 1024);

    // Allocate something
    void *p1 = mem_pool_alloc(&pool);
    CHECK(p1 != nullptr);

    // Allocate more
    void *p2 = mem_pool_alloc(&pool);
    CHECK(p2 != nullptr);
    CHECK(p1 != p2);

    // Free and reallocate
    mem_pool_free(&pool, p1);
    void *p3 = mem_pool_alloc(&pool);
    CHECK(p3 == p1); // Should reuse p1

    mem_pool_free(&pool, p2);
    mem_pool_free(&pool, p3);
  }
}
