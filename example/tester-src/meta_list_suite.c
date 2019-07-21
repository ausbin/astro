#include "suites.h"
#include "../list.h"

/// list_new() meta-tests ///

TEST_START(meta_test_list_new__null,
           "test_list_new catches NULL return value") {
    meta_test_mock_func(list_new, list_new__null);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("should not return NULL", astro_err,
                                  "Tester needs to show good error message "
                                  "on NULL");
} TEST_END

TEST_START(meta_test_list_new__freed,
           "test_list_new catches free()d list") {
    meta_test_mock_func(list_new, list_new__freed);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("points to a freed heap block", astro_err,
                                  "Tester should tell students not to free "
                                  "the result");
} TEST_END

TEST_START(meta_test_list_new__doubly_freed,
           "test_list_new catches double free()") {
    meta_test_mock_func(list_new, list_new__doubly_freed);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("Double free", astro_err,
                                  "Tester should tell students not to double "
                                  "free");
} TEST_END

TEST_START(meta_test_list_new__uninit,
           "test_list_new catches uninitialized memory") {
    meta_test_mock_func(list_new, list_new__uninit);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("size 0", astro_err,
                                  "Tester should tell students not to "
                                  "initialize memory");
} TEST_END

TEST_START(meta_test_list_new__stack,
           "test_list_new catches pointer to stack") {
    meta_test_mock_func(list_new, list_new__stack);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("stack", astro_err,
                                  "Tester should tell students not to "
                                  "return pointer to stack");
} TEST_END

TEST_START(meta_test_list_new__writable_static,
           "test_list_new catches pointer to r/w static memory") {
    meta_test_mock_func(list_new, list_new__writable_static);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("writable static", astro_err,
                                  "Tester should tell students not to "
                                  "return pointer to r/w static memory");
} TEST_END

TEST_START(meta_test_list_new__readonly_static,
           "test_list_new catches pointer to r/o static memory") {
    meta_test_mock_func(list_new, list_new__readonly_static);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("read-only static", astro_err,
                                  "Tester should tell students not to "
                                  "return pointer to r/o static memory");
} TEST_END

TEST_START(meta_test_list_new__stray_heap,
           "test_list_new catches pointer to middle of heap block") {
    meta_test_mock_func(list_new, list_new__stray_heap);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("does not point to the beginning", astro_err,
                                  "Tester should tell students not to "
                                  "return pointer to middle of heap block");
} TEST_END

TEST_START(meta_test_list_new__undersized,
           "test_list_new catches pointer to undersized heap block") {
    meta_test_mock_func(list_new, list_new__undersized);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("incorrect size", astro_err,
                                  "Tester should tell students not to "
                                  "return pointer to tiny heap block");
} TEST_END

TEST_START(meta_test_list_new__oversized,
           "test_list_new catches pointer to oversized heap block") {
    meta_test_mock_func(list_new, list_new__oversized);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("incorrect size", astro_err,
                                  "Tester should tell students not to "
                                  "return pointer to huge heap block");
} TEST_END

TEST_START(meta_test_list_new__leak,
           "test_list_new catches memory leak") {
    meta_test_mock_func(list_new, list_new__leak);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("leak", astro_err,
                                  "Tester should tell students not to "
                                  "leak memory");
} TEST_END

TEST_START(meta_test_list_new__bad_free,
           "test_list_new catches bad free") {
    meta_test_mock_func(list_new, list_new__bad_free);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("free()ing garbage pointer", astro_err,
                                  "Tester should warn students not to "
                                  "free garbage");
} TEST_END

TEST_START(meta_test_list_new__infiniloop,
           "test_list_new catches infinite loop") {
    meta_test_mock_func(list_new, list_new__infiniloop);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new);
    meta_test_assert_err_contains("infinite loop", astro_err,
                                  "Tester should tell students they have "
                                  "infinite loops");
} TEST_END

TEST_START(meta_test_list_new_oom__stack,
           "test_list_new_oop catches not calling malloc") {
    meta_test_mock_func(list_new, list_new__stack);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new_oom);
    meta_test_assert_err_contains("when malloc() does", astro_err,
                                  "Tester should tell students to return NULL "
                                  "when malloc() does");
} TEST_END

TEST_START(meta_test_list_new_oom__segfault,
           "test_list_new_oop causes segfault when dereferencing NULL") {
    meta_test_mock_func(list_new, list_new__oom_segfault);
    const astro_err_t *astro_err = meta_test_run_test(test_list_new_oom);
    meta_test_assert_err_contains("Segmentation Fault", astro_err,
                                  "Tester should catch students dereferencing "
                                  "NULL");
} TEST_END

/// list_push() meta-tests ///

TEST_START(meta_test_list_push_empty__free_list,
           "test_list_push_empty catches free()ing input list") {
    meta_test_mock_func(list_push, list_push__free_list);
    const astro_err_t *astro_err = meta_test_run_test(test_list_push_empty);
    meta_test_assert_err_contains("not allowed to free", astro_err,
                                  "Tester needs to catch free()ing list "
                                  "pointer");
} TEST_END

TEST_START(meta_test_list_push_empty__free_data,
           "test_list_push_empty catches free()ing input list") {
    meta_test_mock_func(list_push, list_push__free_data);
    const astro_err_t *astro_err = meta_test_run_test(test_list_push_empty);
    meta_test_assert_err_contains("not allowed to free", astro_err,
                                  "Tester needs to catch free()ing data "
                                  "pointer");
} TEST_END

void add_meta_list_suite(tester_t *tester) {
    tester_push(tester, meta_test_list_new__null);
    tester_push(tester, meta_test_list_new__freed);
    tester_push(tester, meta_test_list_new__doubly_freed);
    tester_push(tester, meta_test_list_new__uninit);
    tester_push(tester, meta_test_list_new__stack);
    tester_push(tester, meta_test_list_new__writable_static);
    tester_push(tester, meta_test_list_new__readonly_static);
    tester_push(tester, meta_test_list_new__stray_heap);
    tester_push(tester, meta_test_list_new__undersized);
    tester_push(tester, meta_test_list_new__oversized);
    tester_push(tester, meta_test_list_new__leak);
    tester_push(tester, meta_test_list_new__bad_free);
    tester_push(tester, meta_test_list_new__infiniloop);

    tester_push(tester, meta_test_list_new_oom__stack);
    tester_push(tester, meta_test_list_new_oom__segfault);

    tester_push(tester, meta_test_list_push_empty__free_list);
}
