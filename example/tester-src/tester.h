#ifndef TESTER_H
#define TESTER_H

#include <stdio.h>
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

#define test_assert(cond, message) \
    if (!(cond)) \
        return astro_errorf(__astro, \
                            "%s: FAIL. %s\n\tFailing condition: %s. %s", \
                            __test->name, __test->description, #cond, message);

// This is a gcc extension, "statement expressions"
#define test_call(func_name, ...) ({ \
    const astro_err_t *astro_err; \
    uint64_t ret; \
    size_t n = sizeof (uint64_t[]){__VA_ARGS__} / sizeof (uint64_t); \
    if ((astro_err = astro_call_function(__astro, &ret, n, #func_name, ##__VA_ARGS__))) \
        return astro_err; \
    ret; \
})

#define tester_push(tester, test_name) \
    _tester_push(tester, &_ ## test_name)

extern tester_t *tester_new(const char *elf_path);
extern void tester_free(tester_t *);
extern void _tester_push(tester_t *, test_t *test);
extern test_t *tester_get_test(tester_t *tester, const char *test_name);
extern const astro_err_t *tester_run_test(tester_t *tester, test_t *test);

#endif
