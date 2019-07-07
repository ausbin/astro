#ifndef TESTER_H
#define TESTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    const astro_err_t *test_name(test_t *__test, astro_t *__astro); \
    test_t _ ## test_name = { #test_name, test_description, test_name }; \
    const astro_err_t *test_name(test_t *__test, astro_t *__astro) { \
        (void)__test; \
        (void)__astro;
#define TEST_END \
        return NULL; \
    }

#define __assertion_failure(message, format_str, ...) \
    return astro_errorf(__astro, \
                        "Assertion failure in %s at %s:%d. %s\n\tFailing " \
                        "condition: " format_str "\n\tFailing condition " \
                        "description: %s", \
                        __test->name, __FILE__, __LINE__, \
                        __test->description, ##__VA_ARGS__, \
                        (message));

#define test_assert(cond, message) \
    if (!(cond)) \
        __assertion_failure("%s. %s", #cond, (message));

#define test_assert_uint_equals(expected, actual, message) ({ \
    uint64_t _expected = (expected); \
    uint64_t _actual = (actual); \
    if ((expected) != (actual)) \
        __assertion_failure((message), \
                            "expected value %lu, got %lu", \
                            (_expected), (_actual)); \
})

#define test_assert_uint_not_equals(unexpected, actual, message) ({ \
    uint64_t _unexpected = (unexpected); \
    uint64_t _actual = (actual); \
    if ((expected) != (actual)) \
        __assertion_failure((message), \
                            "value was %lu, which is incorrect", \
                            (_unexpected)); \
})

#define test_assert_addr_equals(expected, actual, message) \
    if ((expected) != (actual)) \
        __assertion_failure((message), \
                            "expected address 0x%lx, got 0x%lx", \
                            (expected), (actual));

#define test_assert_addr_not_equals(unexpected, actual, message) \
    if ((unexpected) == (actual)) \
        __assertion_failure((message), \
                            "address was 0x%lx, which is incorrect", \
                            (unexpected));

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

#define test_assert_malloced_block(ptr, size, message) ({ \
    if (astro_is_stack_pointer(__astro, (ptr))) \
        __assertion_failure((message), \
                            "address 0x%lx points to the stack (for " \
                            "example, a local variable) instead of a " \
                            "malloc()d heap block", (ptr)) \
    if (astro_is_rw_static_pointer(__astro, (ptr))) \
        __assertion_failure((message), \
                            "address 0x%lx points to writable static memory " \
                            "(for example, a global variable) instead of a " \
                            "malloc()d heap block", (ptr)) \
    if (astro_is_ro_static_pointer(__astro, (ptr))) \
        __assertion_failure((message), \
                            "address 0x%lx points to read-only static " \
                            "memory (for example, a string literal) instead " \
                            "of a malloc()d heap block", (ptr)) \
    if (astro_is_freed_block(__astro, (ptr))) \
        __assertion_failure((message), \
                            "address 0x%lx points to a freed heap block " \
                            "instead of a malloc()d heap block", (ptr)) \
    if (!astro_is_malloced_block(__astro, (ptr))) \
        __assertion_failure((message), \
                            "address 0x%lx does not point to the beginning " \
                            "of a malloc()d heap block", (ptr)) \
    \
    uint64_t actual_size; \
    const astro_err_t *astro_err; \
    if ((astro_err = astro_malloced_block_size(__astro, (ptr), &actual_size))) \
        return astro_err; \
    \
    if ((actual_size) != (size)) \
        __assertion_failure((message), \
                            "heap block at address 0x%lx has incorrect size " \
                            "%lu instead of expected size %lu", (ptr), \
                            (actual_size), (size)); \
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

// TODO: what if this is too big for the stack?
#define test_read_mem(ptr, size) ({ \
    uint8_t mem[(size)]; \
    const astro_err_t *astro_err; \
    if ((astro_err = astro_read_mem(__astro, (ptr), (size), (uint64_t *) mem))) \
        return astro_err; \
    \
    (void *) mem; \
})

#define tester_push(tester, test_name) \
    _tester_push(tester, &_ ## test_name)

extern tester_t *tester_new(const char *elf_path);
extern void tester_free(tester_t *);
extern void _tester_push(tester_t *, test_t *test);
extern test_t *tester_get_test(tester_t *tester, const char *test_name);
extern const astro_err_t *tester_run_test(tester_t *tester, test_t *test);
extern const astro_err_t *tester_run_all_tests(tester_t *tester);

//// meta testing functions/macros ////

#define meta_test_mock_func(func_name, mock_func_name) ({ \
    const astro_err_t *astro_err; \
    if ((astro_err = astro_mock_func(__astro, #func_name, #mock_func_name))) \
        return astro_err; \
})

// This is a hack to write tests of tests without a pointer to the tester_t.
// We can abuse the linker to call other tests.
#define meta_test_run_test(test_name) ({ \
    extern const astro_err_t *test_name(test_t *, astro_t *); \
    extern test_t _ ## test_name; \
    test_name(&_ ## test_name, __astro); \
})

#define meta_test_assert_err_contains(substr, astro_err, message) ({ \
    if (!(astro_err)) \
        __assertion_failure((message), "expected an error but got NULL"); \
    \
    if (!strstr((astro_err)->msg, (substr))) { \
        char buf[2 * strlen((astro_err)->msg) + 1]; \
        astro_escape_str((astro_err)->msg, buf); \
        __assertion_failure((message), \
                            "expected substring `%s' not found in error " \
                            "message `%s'", \
                            (substr), buf); \
    } \
})

#endif
