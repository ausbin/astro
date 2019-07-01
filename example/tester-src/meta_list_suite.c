#include "suites.h"
#include "../list.h"

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

void add_meta_list_suite(tester_t *tester) {
    tester_push(tester, meta_test_list_new__null);
    tester_push(tester, meta_test_list_new__freed);
}
