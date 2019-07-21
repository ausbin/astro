#ifndef TESTER_H
#define TESTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <astro.h>

#define CMP(left, right) (((left) > (right)) ? 1 : ((left) < (right))? -1 : 0)
// Less repetitive than casting to uint64_t everywhere
#define ADDR(ptr) ((uint64_t) (ptr))

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

typedef struct {
    uint64_t addr;
    //size_t size;
    const char *description;
} _tester_heap_state_t;

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

#define test_assert_int_equals(expected, actual, message) ({ \
    int64_t _expected = (expected); \
    int64_t _actual = (actual); \
    if ((expected) != (actual)) \
        __assertion_failure((message), \
                            "%s: expected value %ld, got %ld", \
                            #actual, (_expected), (_actual)); \
})

#define test_assert_int_not_equals(unexpected, actual, message) ({ \
    uint64_t _unexpected = (unexpected); \
    uint64_t _actual = (actual); \
    if ((expected) == (actual)) \
        __assertion_failure((message), \
                            "%s: value was %ld, which is incorrect", \
                            #actual, (_unexpected)); \
})

#define test_assert_uint_equals(expected, actual, message) ({ \
    uint64_t _expected = (expected); \
    uint64_t _actual = (actual); \
    if ((expected) != (actual)) \
        __assertion_failure((message), \
                            "%s: expected value %lu, got %lu", \
                            #actual, (_expected), (_actual)); \
})

#define test_assert_uint_not_equals(unexpected, actual, message) ({ \
    uint64_t _unexpected = (unexpected); \
    uint64_t _actual = (actual); \
    if ((expected) == (actual)) \
        __assertion_failure((message), \
                            "%s: value was %lu, which is incorrect", \
                            #actual, (_unexpected)); \
})

#define test_assert_addr_equals(expected, actual, message) \
    if ((expected) != (actual)) \
        __assertion_failure((message), \
                            "%s: expected address 0x%lx, got 0x%lx", \
                            #actual, (expected), (actual));

#define test_assert_addr_not_equals(unexpected, actual, message) \
    if ((unexpected) == (actual)) \
        __assertion_failure((message), \
                            "%s: address was 0x%lx, which is incorrect", \
                            #actual, (unexpected));

#define test_make_heap_block(ptr, size, freeable) ({ \
    const astro_err_t *astro_err; \
    uint64_t addr; \
    if ((astro_err = astro_malloc((__astro), (size), (freeable), &(addr)))) \
        return astro_err; \
    if ((astro_err = astro_write_mem((__astro), (addr), (size), (ptr)))) \
        return astro_err; \
    addr; \
})

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
    uint64_t addr = (uint64_t) (ptr); \
    \
    if (astro_is_stack_pointer(__astro, addr)) \
        __assertion_failure((message), \
                            "address 0x%lx points to the stack (for " \
                            "example, a local variable) instead of a " \
                            "malloc()d heap block", addr) \
    if (astro_is_rw_static_pointer(__astro, addr)) \
        __assertion_failure((message), \
                            "address 0x%lx points to writable static memory " \
                            "(for example, a global variable) instead of a " \
                            "malloc()d heap block", addr) \
    if (astro_is_ro_static_pointer(__astro, addr)) \
        __assertion_failure((message), \
                            "address 0x%lx points to read-only static " \
                            "memory (for example, a string literal) instead " \
                            "of a malloc()d heap block", addr) \
    if (astro_is_freed_block(__astro, addr)) \
        __assertion_failure((message), \
                            "address 0x%lx points to a freed heap block " \
                            "instead of a malloc()d heap block", addr) \
    if (!astro_is_malloced_block(__astro, addr)) \
        __assertion_failure((message), \
                            "address 0x%lx does not point to the beginning " \
                            "of a malloc()d heap block", addr) \
    \
    uint64_t actual_size; \
    const astro_err_t *astro_err; \
    if ((astro_err = astro_malloced_block_size(__astro, addr, &actual_size))) \
        return astro_err; \
    \
    if ((actual_size) != (size)) \
        __assertion_failure((message), \
                            "heap block at address 0x%lx has incorrect size " \
                            "%lu instead of expected size %lu", addr, \
                            (actual_size), (size)); \
})

#define test_assert_heap_state(message, ...) ({ \
    _tester_heap_state_t heap_state_args[] = {__VA_ARGS__}; \
    size_t total_blocks = sizeof heap_state_args / \
                          sizeof (_tester_heap_state_t); \
    char errmsg[2048]; \
    if (!_tester_assert_heap_state(__astro, heap_state_args, total_blocks, \
                                   errmsg, sizeof errmsg)) { \
        __assertion_failure((message), \
                            "found unexpected blocks on the heap. " \
                            "this could indicate a memory leak! list of " \
                            "unknown blocks:\n%s", errmsg); \
    } \
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

#define test_read_mem(addr, ptr, size) ({ \
    const astro_err_t *astro_err; \
    if ((astro_err = astro_read_mem(__astro, (uint64_t ) (addr), (size), (ptr)))) \
        return astro_err; \
})

#define tester_set_mallocs_until_fail(mallocs_until_fail) \
    astro_set_mallocs_until_fail(__astro, mallocs_until_fail);

#define tester_push(tester, test_name) \
    _tester_push(tester, &_ ## test_name)

extern tester_t *tester_new(const char *elf_path);
extern void tester_free(tester_t *);
extern void _tester_push(tester_t *, test_t *test);
extern test_t *tester_get_test(tester_t *tester, const char *test_name);
extern const astro_err_t *tester_run_test(tester_t *tester, test_t *test);
extern const astro_err_t *tester_run_all_tests(tester_t *tester);
extern bool _tester_assert_heap_state(astro_t *astro,
                                      _tester_heap_state_t *heap_state_args,
                                      size_t total_blocks, char *errmsg_out,
                                      size_t errmsg_size);

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
