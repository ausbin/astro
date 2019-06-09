#ifndef TESTER_H
#define TESTER_H

#include <stdio.h>
#include <stdlib.h>
#include <astro.h>

typedef struct test test_t;

typedef const astro_err_t *(*tester_func_t)(test_t *, astro_t *);

struct test {
    const char *name;
    const char *description;
    tester_func_t func;
};

#define TESTER_TESTS_GROWTH_FACTOR 2

typedef struct {
    const char *elf_path;
    unsigned int tests_count;
    unsigned int tests_cap;
    test_t *tests;
} tester_t;

#define TEST_START(test_name, test_description) \
    static const astro_err_t *test_name(test_t *__test, astro_t *__astro); \
    static test_t _ ## test_name = { #test_name, test_description, test_name }; \
    static const astro_err_t *test_name(test_t *__test, astro_t *__astro) { \
        (void)__test; \
        (void)__astro;
#define TEST_END \
        return NULL; \
    }

#define __assertion_failure(format_str, ...) \
    return astro_errorf(__astro, \
                        "Assertion failure in %s at %s:%d. %s\n\tFailing " \
                        "condition: " format_str, \
                        __test->name, __FILE__, __LINE__, \
                        __test->description, ##__VA_ARGS__);

#define test_assert(cond, message) \
    if (!(cond)) \
        __assertion_failure("%s. %s", #cond, (message));

#define test_assert_uint_equals(expected, actual, message) ({ \
    uint64_t _expected = (expected); \
    uint64_t _actual = (actual); \
    if ((expected) != (actual)) \
        __assertion_failure("expected value %lu, got %lu. %s", \
                            (_expected), (_actual), (message)); \
})

#define test_assert_uint_not_equals(unexpected, actual, message) ({ \
    uint64_t _unexpected = (unexpected); \
    uint64_t _actual = (actual); \
    if ((expected) != (actual)) \
        __assertion_failure("value was %lu, which is incorrect. %s", \
                            (_unexpected), (message)); \
})

#define test_assert_addr_equals(expected, actual, message) \
    if ((expected) != (actual)) \
        __assertion_failure("expected address 0x%lx, got 0x%lx. %s", \
                            (expected), (actual), (message));

#define test_assert_addr_not_equals(unexpected, actual, message) \
    if ((unexpected) == (actual)) \
        __assertion_failure("address was 0x%lx, which is incorrect. %s", \
                            (unexpected), (message));

#define test_is_malloced_block(ptr, size) ({ \
    if (!astro_is_malloced_block(__astro, (ptr))) \
        return false; \
    \
    uint64_t actual_size; \
    const astro_err_t *astro_err; \
    if ((astro_err = astro_malloced_block_size(__astro, (ptr), &actual_size))) \
        return astro_err; \
    \
    (actual_size == (size)); \
})

// This is a gcc extension, "statement expressions"
#define test_call(func_name, ...) ({ \
    const astro_err_t *astro_err; \
    uint64_t ret; \
    size_t n = sizeof (uint64_t[]){__VA_ARGS__} / sizeof (uint64_t); \
    if ((astro_err = astro_call_function(__astro, &ret, n, #func_name, ##__VA_ARGS__))) \
        return astro_err; \
    ret; \
})

#define test_read_mem(ptr, size) ({ \
    void *block = malloc((size)); \
    if (!block) \
        return astro_perror(__astro, "malloc"); \
    \
    const astro_err_t *astro_err; \
    if ((astro_err = astro_read_mem(__astro, (ptr), (size), block))) \
        return astro_err; \
    \
    block; \
})

#define tester_push(tester, test_name) \
    _tester_push(tester, &_ ## test_name)

extern tester_t *tester_new(const char *elf_path);
extern void tester_free(tester_t *);
extern void _tester_push(tester_t *, test_t *test);
extern test_t *tester_get_test(tester_t *tester, const char *test_name);
extern const astro_err_t *tester_run_test(tester_t *tester, test_t *test);

#endif
