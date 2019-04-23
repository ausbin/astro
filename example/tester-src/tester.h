#ifndef TESTER_H
#define TESTER_H

typedef int (*tester_func_t)(void);

typedef struct {
    const char *name;
    const char *description;
    tester_func_t func;
} test_t;

#define TESTER_TESTS_GROWTH_FACTOR 2

typedef struct {
    unsigned int tests_count;
    unsigned int tests_cap;
    test_t *tests;
} tester_t;

#define TEST_START(test_name) \
    int test_name(void) {
#define TEST_END \
        return 1; \
    }

#define test_assert(cond, message) \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s. Failing condition: %s\n", message, #cond); \
        return 0; \
    }

extern tester_t *tester_new(void);
extern void tester_free(tester_t *);

#endif
