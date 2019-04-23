#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tester.h"

tester_t *tester_new(void) {
    tester_t *tester = calloc(1, sizeof (tester_t));
    if (!tester) {
        perror("calloc");
        abort();
    }
    return tester;
}

void tester_free(tester_t *tester) {
    if (!tester)
        return;

    free(tester->tests);
    free(tester);
}

void tester_push(tester_t *tester, test_t *test) {
    if (!tester || !test)
        return;

    // Need to grow this boy
    if (tester->tests_count == tester->tests_cap) {
        tester->tests_cap *= TESTER_TESTS_GROWTH_FACTOR;
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
