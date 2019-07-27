#include <stdio.h>
#include <stdlib.h>
#include <astro.h>
#include "tester.h"
#include "suites.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s <test_name>\n", prog);
    // TODO: print available tests
}

static int run_test(tester_t *tester, test_t *test, int blank_line) {
    const astro_err_t *astro_err = tester_run_test(tester, test);
    if (astro_err) {
        if (blank_line)
            printf("\n");
        astro_print_err(stderr, astro_err);
    }
    return !!astro_err;
}

int main(int argc, char **argv) {
    char *test_name = NULL;

    if (argc-1 == 1) {
        test_name = argv[1];
    } else if (argc-1 > 1) {
        print_usage(argv[0]);
        return 1;
    }

    tester_t *tester = tester_new("student.elf");
    add_list_suite(tester);
    add_meta_list_suite(tester);

    int exit_code = 0;

    if (test_name) {
        test_t *test;
        if (!(test = tester_get_test(tester, argv[1]))) {
            fprintf(stderr, "error: unknown test `%s'\n", argv[1]);
            exit_code = 1;
        } else {
            exit_code = run_test(tester, test, 0);
        }
    } else {
        for (unsigned int i = 0; i < tester->tests_count; i++) {
            test_t *test = &tester->tests[i];
            exit_code = run_test(tester, test, exit_code) || exit_code;
        }
    }

    tester_free(tester);

    // Print something on success to avoid student confusion
    if (!exit_code)
        printf("tests passed! nice work\n");

    return exit_code;
}
