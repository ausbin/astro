#include <stdio.h>
#include <stdlib.h>
#include <astro.h>
#include "tester.h"
#include "suites.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s                    (run all tests)\n", prog);
    fprintf(stderr, "       %s <test name>        (run single test)\n", prog);
    fprintf(stderr, "       %s --gdb <test name>  (start gdb server for test)\n", prog);
    // TODO: print available tests
}

static int run_test(tester_t *tester, test_t *test, bool gdb, int blank_line) {
    const astro_err_t *astro_err;

    astro_err = tester_run_test(tester, test, gdb);

    if (astro_err) {
        if (blank_line)
            printf("\n");

        fprintf(stderr, "Failed test %s: %s:\n", test->name,
                                                 test->description);
        astro_print_err(stderr, "    ", astro_err);
    }
    return !!astro_err;
}

int main(int argc, char **argv) {
    char *test_name = NULL;
    bool gdb = false;

    int nargs = argc-1;
    if (nargs == 1) {
        test_name = argv[1];
    } else if (nargs == 2 && !strcmp(argv[1], "--gdb")) {
        test_name = argv[2];
        gdb = true;
    } else if (nargs > 0) {
        print_usage(argv[0]);
        return 1;
    }

    tester_t *tester = tester_new("student.elf");
    add_list_suite(tester);
    add_meta_list_suite(tester);

    int exit_code = 0;

    if (test_name) {
        test_t *test;
        if (!(test = tester_get_test(tester, test_name))) {
            fprintf(stderr, "error: unknown test `%s'\n", test_name);
            exit_code = 1;
        } else {
            exit_code = run_test(tester, test, gdb, 0);
        }
    } else {
        for (unsigned int i = 0; i < tester->tests_count; i++) {
            test_t *test = &tester->tests[i];
            exit_code = run_test(tester, test, gdb, exit_code) || exit_code;
        }
    }

    tester_free(tester);

    // Print something on success to avoid student confusion
    if (!exit_code)
        printf("tests passed! nice work\n");

    return exit_code;
}
