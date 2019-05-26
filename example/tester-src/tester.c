#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tester.h"

static void backtrace(astro_t *astro, void *user_data) {
    (void)user_data;

    const astro_err_t *astro_err;

    if ((astro_err = astro_stub_print_backtrace(astro)))
        goto failure;

    return;

    failure:
    astro_stub_die(astro, astro_err);
}

tester_t *tester_new(const char *elf_path) {
    tester_t *tester = calloc(1, sizeof (tester_t));
    if (!tester) {
        perror("calloc");
        abort();
    }
    tester->elf_path = elf_path;
    return tester;
}

void tester_free(tester_t *tester) {
    if (!tester)
        return;

    free(tester->tests);
    free(tester);
}

void _tester_push(tester_t *tester, test_t *test) {
    if (!tester || !test)
        return;

    // Need to grow this boy
    if (tester->tests_count == tester->tests_cap) {
        tester->tests_cap = tester->tests_cap * TESTER_TESTS_GROWTH_FACTOR + 1;
        tester->tests = realloc(tester->tests,
                                tester->tests_cap * sizeof (test_t));
        // Oopsie daisy, did I just leak? Damn right I did!
        if (!tester->tests) {
            perror("realloc");
            abort();
        }
    }

    memcpy(&tester->tests[tester->tests_count], test, sizeof (test_t));
    tester->tests_count++;
}

test_t *tester_get_test(tester_t *tester, const char *test_name) {
    for (unsigned int i = 0; i < tester->tests_count; i++)
        if (!strcmp(test_name, tester->tests[i].name))
            return &tester->tests[i];

    return NULL;
}

int tester_run_test(tester_t *tester, test_t *test) {
    astro_t *astro;
    const astro_err_t *astro_err;

    if ((astro_err = astro_new(tester->elf_path, &astro)))
        goto failure;

    if ((astro_err = astro_stub_setup(astro, NULL, "__backtrace", backtrace)))
        goto failure;

    int ret = test->func(test, astro);
    astro_free(astro);
    return ret;

    failure:
    astro_print_err(stderr, astro_err);
    astro_free(astro);
    return 0;
}
