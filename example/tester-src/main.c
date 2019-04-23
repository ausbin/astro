#include <stdio.h>
#include <stdlib.h>
#include <astro.h>
#include "tester.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "usage: %s <test_name>\n", prog);
    // TODO: print available tests
}

static void backtrace(astro_t *astro, void *user_data) {
    (void)user_data;

    if (!astro_stub_print_backtrace(astro))
        goto failure;

    return;

    failure:
    astro_stub_die(astro);
}

static int run_test(const char *name) {
    astro_t *astro = astro_new("student.elf");

    if (!astro)
        goto failure;

    if (!astro_stub_setup(astro, NULL, "__backtrace", backtrace))
        goto failure;

    (void)name;
    if (!astro_call_function(astro, NULL, 0, "asdf"))
        goto failure;

    astro_free(astro);
    return 1;

    failure:
    astro_free(astro);
    return 0;
}

int main(int argc, char **argv) {
    if (argc-1 != 1) {
        print_usage(argv[0]);
        return 1;
    }

    tester_t *tester = tester_new();
    //add_list_suite(tester);
    int ret = !run_test(argv[1]);
    tester_free(tester);
    return ret;
}
