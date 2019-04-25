#include "suites.h"

TEST_START(test_list_new, "list_new() should return a pointer to a new struct") {
    test_assert(1 == 2, "one should equal two");
} TEST_END

void add_list_suite(tester_t *tester) {
    tester_push(tester, test_list_new);
}
