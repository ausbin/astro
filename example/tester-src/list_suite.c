#include "suites.h"

TEST_START(test_list_new,
           "list_new() should return a pointer to a new struct on the heap") {
    uint64_t list_ptr = test_call(list_new);
    test_assert(list_ptr != 0, "new_list() should not return NULL");
} TEST_END

void add_list_suite(tester_t *tester) {
    tester_push(tester, test_list_new);
}
