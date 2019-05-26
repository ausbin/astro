#include <stdio.h>
#include <stdlib.h>
#include <astro.h>
#include "tester.h"
#include "suites.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s <test_name>\n", prog);
    // TODO: print available tests
}

int main(int argc, char **argv) {
    if (argc-1 != 1) {
        print_usage(argv[0]);
        return 1;
    }

    tester_t *tester = tester_new("student.elf");
    add_list_suite(tester);

    test_t *test;
    if (!(test = tester_get_test(tester, argv[1]))) {
        fprintf(stderr, "error: unknown test `%s'\n", argv[1]);
        return 1;
    }

    const astro_err_t *astro_err = tester_run_test(tester, test);
    if (astro_err)
        astro_print_err(stderr, astro_err);
    tester_free(tester);
    return !!astro_err;
}
