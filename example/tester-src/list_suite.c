#include "suites.h"
#include "../list.h"

TEST_START(test_list_new,
           "list_new() should return a pointer to an empty list on the heap") {

    uint64_t list_ptr = test_call(list_new);
    // TODO: make an equals macro to print both values
    test_assert(list_ptr != 0, "list_new() should not return NULL");
    test_assert(test_is_malloced_block(list_ptr, sizeof (list_t)),
                "list_new() should return a malloc()d block the size of a "
                "list_t)");

    list_t *list = test_read_mem(list_ptr, sizeof (list_t));
    test_assert(list->size == 0, "list_new() should return a list with size 0");
    test_assert(list->head == NULL, "list_new() should return a list with a "
                                    "NULL head pointer");
} TEST_END

void add_list_suite(tester_t *tester) {
    tester_push(tester, test_list_new);
}
