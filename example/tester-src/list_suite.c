#include "suites.h"
#include "../list.h"

/// list_new() tests ///
HELPER_START(make_test_list,
             size_t size, uint64_t *list_addr_out,
             uint64_t *data_addrs_out, uint64_t *node_addrs_out) {
    static const int data_values[] = {-1, 69, 420, 1024, -1025};

    uint64_t next_node_addr = 0;

    for (size_t i = 0; i < size; i++) {
        int data = data_values[i % (sizeof data_values / sizeof *data_values)];

        uint64_t data_addr = test_make_heap_block(&data, sizeof data,
                                                  UNACCESSIBLE, NOT_FREEABLE);
        list_node_t node = { .data = PTR(data_addr), .next = PTR(next_node_addr) };
        uint64_t node_addr = test_make_heap_block(&node, sizeof node,
                                                  READABLE, NOT_FREEABLE);

        next_node_addr = node_addr;
        data_addrs_out[size - 1 - i] = data_addr;
        node_addrs_out[size - 1 - i] = node_addr;
    }

    list_t list = { .size = size, .head = PTR(next_node_addr) };
    *list_addr_out = test_make_heap_block(&list, sizeof list, WRITABLE,
                                          NOT_FREEABLE);
} HELPER_END

TEST_START(test_list_new,
           "list_new() should return a pointer to an empty list on the heap") {

    uint64_t list_addr = test_call(list_new);
    test_assert_addr_not_equals(0, list_addr,
                                "list_new() should not return NULL");
    test_assert_malloced_block(list_addr, sizeof (list_t),
                               "list_new() should return a malloc()'d block "
                               "the size of a list_t)");

    list_t list;
    test_read_mem(list_addr, &list, sizeof list);
    test_assert_uint_equals(0, list.size,
                            "list_new() should return a list with size 0");
    test_assert(list.head == NULL, "list_new() should return a list with a "
                                    "NULL head pointer");
    test_assert_heap_state("list_new() should not leak memory",
                           {list_addr, "list_t struct"});
} TEST_END

TEST_START(test_list_new_oom,
           "list_new() should return NULL when out of memory") {

    tester_set_mallocs_until_fail(0);

    uint64_t list_addr = test_call(list_new);
    // TODO: make an equals macro to print both values
    test_assert_addr_equals(0, list_addr,
                            "list_new() should return NULL when malloc() "
                            "does");
    test_assert_heap_state("list_new() should not allocate memory"
                           /* no blocks */);
} TEST_END

/// list_push() tests ///

TEST_START(test_list_push_empty_list,
           "list_push() should insert an element at the beginning of an empty "
           "list") {

    list_t list = { .size = 0, .head = NULL };
    uint64_t list_addr = test_make_heap_block(&list, sizeof list, WRITABLE,
                                              NOT_FREEABLE);
    int new_data = 69;
    uint64_t new_data_addr = test_make_heap_block(&new_data, sizeof new_data,
                                                  UNACCESSIBLE, NOT_FREEABLE);

    int ret = (int) test_call(list_push, list_addr, new_data_addr);
    test_read_mem(list_addr, &list, sizeof list);

    test_assert_int_equals(1, ret, "list_push() should return 1 for success");
    test_assert_uint_equals(1, list.size,
                            "list_push() should increment the size of the list");
    test_assert_addr_not_equals(0, ADDR(list.head),
                                "list->head should not be NULL, since "
                                "list_push() should set a new head node.");
    test_assert_malloced_block(ADDR(list.head), sizeof (list_node_t),
                               "list_push() should set list->head to point to "
                               "a malloc()d list_node_t (the new node)");

    list_node_t head_node;
    test_read_mem(list.head, &head_node, sizeof head_node);

    test_assert_addr_equals(0, ADDR(head_node.next),
                            "list_push() should set list->head->next to NULL, "
                            "since the new node is the last node");
    test_assert_addr_equals(new_data_addr, ADDR(head_node.data),
                            "list_push() points list->head->data to the data "
                            "pointer passed in");

    test_assert_heap_state("list_push() should allocate only the new node",
                           {list_addr, "list_t struct passed in"},
                           {new_data_addr, "data passed in"},
                           {ADDR(list.head), "list_node_t struct created"});
} TEST_END

TEST_START(test_list_push_singleton_list,
           "list_push() should insert an element at the beginning of a list "
           "containing only element") {

    uint64_t list_addr, data_addr, node_addr;
    test_call_helper(make_test_list, 1, &list_addr, &data_addr, &node_addr);

    int new_data = 69;
    uint64_t new_data_addr = test_make_heap_block(&new_data, sizeof new_data,
                                                  UNACCESSIBLE, NOT_FREEABLE);

    int ret = (int) test_call(list_push, list_addr, data_addr);
    list_t list;
    test_read_mem(list_addr, &list, sizeof list);

    test_assert_int_equals(1, ret, "list_push() should return 1 for success");
    test_assert_uint_equals(2, list.size,
                            "list_push() should increment the size of the list");
    test_assert_addr_not_equals(0, ADDR(list.head),
                                "list->head should not be NULL, since "
                                "list_push() should set a new head node.");
    test_assert_malloced_block(ADDR(list.head), sizeof (list_node_t),
                               "list_push() should set list->head to point to "
                               "a malloc()d list_node_t (the new node)");

    list_node_t head_node;
    test_read_mem(list.head, &head_node, sizeof head_node);

    test_assert_addr_equals(node_addr, ADDR(head_node.next),
                            "list_push() should set list->head->next to the "
                            "address of the original first node, since the "
                            "new node is the new head node");
    test_assert_addr_equals(data_addr, ADDR(head_node.data),
                            "list_push() points list->head->data to the data "
                            "pointer passed in");

    test_assert_heap_state("list_push() should allocate only the new node",
                           {list_addr, "list_t struct passed in"},
                           {data_addr, "data for node #0"},
                           {node_addr, "node #0"},
                           {new_data_addr, "data passed in"},
                           {ADDR(list.head), "list_node_t struct created"});
} TEST_END


TEST_START(test_list_push_nonempty_list,
           "list_push() should insert an element at the beginning of a list "
           "containing three elements") {

    const size_t size = 3;
    uint64_t list_addr, data_addrs[size], node_addrs[size];
    test_call_helper(make_test_list, size, &list_addr, data_addrs, node_addrs);

    int new_data = 69;
    uint64_t new_data_addr = test_make_heap_block(&new_data, sizeof new_data,
                                                  UNACCESSIBLE, NOT_FREEABLE);

    int ret = (int) test_call(list_push, list_addr, new_data_addr);
    list_t list;
    test_read_mem(list_addr, &list, sizeof list);

    test_assert_int_equals(1, ret, "list_push() should return 1 for success");
    test_assert_uint_equals(size + 1, list.size,
                            "list_push() should increment the size of the list");
    test_assert_addr_not_equals(0, ADDR(list.head),
                                "list->head should not be NULL, since "
                                "list_push() should set a new head node.");
    test_assert_malloced_block(ADDR(list.head), sizeof (list_node_t),
                               "list_push() should set list->head to point to "
                               "a malloc()d list_node_t (the new node)");

    list_node_t head_node;
    test_read_mem(list.head, &head_node, sizeof head_node);

    test_assert_addr_equals(node_addrs[0], ADDR(head_node.next),
                            "list_push() should set list->head->next to the "
                            "address of the original first node, since the "
                            "new node is the new head node");
    test_assert_addr_equals(new_data_addr, ADDR(head_node.data),
                            "list_push() points list->head->data to the data "
                            "pointer passed in");

    test_assert_heap_state("list_push() should allocate only the new node",
                           {list_addr, "list_t struct passed in"},
                           {data_addrs[0], "data for node #0"},
                           {node_addrs[0], "node #0"},
                           {data_addrs[1], "data for node #1"},
                           {node_addrs[1], "node #1"},
                           {data_addrs[2], "data for node #2"},
                           {node_addrs[2], "node #2"},
                           {new_data_addr, "data passed in"},
                           {ADDR(list.head), "list_node_t struct created"});
} TEST_END

void add_list_suite(tester_t *tester) {
    tester_push(tester, test_list_new);
    tester_push(tester, test_list_new_oom);

    tester_push(tester, test_list_push_empty_list);
    tester_push(tester, test_list_push_singleton_list);
    tester_push(tester, test_list_push_nonempty_list);
}
