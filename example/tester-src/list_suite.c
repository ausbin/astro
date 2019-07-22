#include "suites.h"
#include "../list.h"

/// list_new() tests ///

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
    uint64_t list_addr = test_make_heap_block(&list, sizeof list, NOT_FREEABLE);
    int data = 69;
    uint64_t data_addr = test_make_heap_block(&data, sizeof data, NOT_FREEABLE);

    int ret = (int) test_call(list_push, list_addr, data_addr);
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
    test_assert_addr_equals(data_addr, ADDR(head_node.data),
                            "list_push() points list->head->data to the data "
                            "pointer passed in");

    test_assert_heap_state("list_push() should allocate only the new node",
                           {list_addr, "list_t struct passed in"},
                           {data_addr, "data passed in"},
                           {ADDR(list.head), "list_node_t struct created"});
} TEST_END

TEST_START(test_list_push_singleton_list,
           "list_push() should insert an element at the beginning of a list "
           "containing only one elements") {

    int data0 = 0xBEEF;
    uint64_t data0_addr = test_make_heap_block(&data0, sizeof data0, NOT_FREEABLE);
    list_node_t node0 = { .data = PTR(data0_addr), .next = NULL };
    uint64_t node0_addr = test_make_heap_block(&node0, sizeof node0, NOT_FREEABLE);

    list_t list = { .size = 3, .head = PTR(node0_addr) };
    uint64_t list_addr = test_make_heap_block(&list, sizeof list, NOT_FREEABLE);

    int data = 69;
    uint64_t data_addr = test_make_heap_block(&data, sizeof data, NOT_FREEABLE);

    int ret = (int) test_call(list_push, list_addr, data_addr);
    test_read_mem(list_addr, &list, sizeof list);

    test_assert_int_equals(1, ret, "list_push() should return 1 for success");
    test_assert_uint_equals(4, list.size,
                            "list_push() should increment the size of the list");
    test_assert_addr_not_equals(0, ADDR(list.head),
                                "list->head should not be NULL, since "
                                "list_push() should set a new head node.");
    test_assert_malloced_block(ADDR(list.head), sizeof (list_node_t),
                               "list_push() should set list->head to point to "
                               "a malloc()d list_node_t (the new node)");

    list_node_t head_node;
    test_read_mem(list.head, &head_node, sizeof head_node);

    test_assert_addr_equals(node0_addr, ADDR(head_node.next),
                            "list_push() should set list->head->next to the "
                            "address of the original first node, since the "
                            "new node is the new head node");
    test_assert_addr_equals(data_addr, ADDR(head_node.data),
                            "list_push() points list->head->data to the data "
                            "pointer passed in");

    test_assert_heap_state("list_push() should allocate only the new node",
                           {list_addr, "list_t struct passed in"},
                           {data0_addr, "data for node #0"},
                           {node0_addr, "node #0"},
                           {data_addr, "data passed in"},
                           {ADDR(list.head), "list_node_t struct created"});
} TEST_END


TEST_START(test_list_push_nonempty_list,
           "list_push() should insert an element at the beginning of a list "
           "containing three elements") {

    int data2 = 0xFF;
    uint64_t data2_addr = test_make_heap_block(&data2, sizeof data2, NOT_FREEABLE);
    list_node_t node2 = { .data = PTR(data2_addr), .next = NULL };
    uint64_t node2_addr = test_make_heap_block(&node2, sizeof node2, NOT_FREEABLE);

    int data1 = 0xAD;
    uint64_t data1_addr = test_make_heap_block(&data1, sizeof data1, NOT_FREEABLE);
    list_node_t node1 = { .data = PTR(data1_addr), .next = PTR(node2_addr) };
    uint64_t node1_addr = test_make_heap_block(&node1, sizeof node1, NOT_FREEABLE);

    int data0 = 0xDE;
    uint64_t data0_addr = test_make_heap_block(&data0, sizeof data0, NOT_FREEABLE);
    list_node_t node0 = { .data = PTR(data0_addr), .next = PTR(node1_addr) };
    uint64_t node0_addr = test_make_heap_block(&node0, sizeof node0, NOT_FREEABLE);

    list_t list = { .size = 3, .head = PTR(node0_addr) };
    uint64_t list_addr = test_make_heap_block(&list, sizeof list, NOT_FREEABLE);

    int data = 69;
    uint64_t data_addr = test_make_heap_block(&data, sizeof data, NOT_FREEABLE);

    int ret = (int) test_call(list_push, list_addr, data_addr);
    test_read_mem(list_addr, &list, sizeof list);

    test_assert_int_equals(1, ret, "list_push() should return 1 for success");
    test_assert_uint_equals(4, list.size,
                            "list_push() should increment the size of the list");
    test_assert_addr_not_equals(0, ADDR(list.head),
                                "list->head should not be NULL, since "
                                "list_push() should set a new head node.");
    test_assert_malloced_block(ADDR(list.head), sizeof (list_node_t),
                               "list_push() should set list->head to point to "
                               "a malloc()d list_node_t (the new node)");

    list_node_t head_node;
    test_read_mem(list.head, &head_node, sizeof head_node);

    test_assert_addr_equals(node0_addr, ADDR(head_node.next),
                            "list_push() should set list->head->next to the "
                            "address of the original first node, since the "
                            "new node is the new head node");
    test_assert_addr_equals(data_addr, ADDR(head_node.data),
                            "list_push() points list->head->data to the data "
                            "pointer passed in");

    test_assert_heap_state("list_push() should allocate only the new node",
                           {list_addr, "list_t struct passed in"},
                           {data0_addr, "data for node #0"},
                           {node0_addr, "node #0"},
                           {data1_addr, "data for node #1"},
                           {node1_addr, "node #1"},
                           {data2_addr, "data for node #2"},
                           {node2_addr, "node #2"},
                           {data_addr, "data passed in"},
                           {ADDR(list.head), "list_node_t struct created"});
} TEST_END

void add_list_suite(tester_t *tester) {
    tester_push(tester, test_list_new);
    tester_push(tester, test_list_new_oom);

    tester_push(tester, test_list_push_empty_list);
    tester_push(tester, test_list_push_singleton_list);
    tester_push(tester, test_list_push_nonempty_list);
}
