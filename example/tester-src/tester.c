#include <stdio.h>
#include <stdlib.h>
#include "astro.h"

static void stubby(astro_t *astro, void *user_data) {
    (void)astro;
    (void)user_data;

    uint64_t n;
    if (!stub_arg(astro, 0, &n))
        goto failure;

    printf("stubby called! n = 0x%lx\n", n);

    return;

    failure:
    stub_die(astro);
}

static void backtrace(astro_t *astro, void *user_data) {
    (void)astro;
    (void)user_data;

    printf("time to backtrace boys!\n");

    if (!stub_print_backtrace(astro))
        goto failure;

    return;

    failure:
    stub_die(astro);
}

int main(void) {
    astro_t *astro = astro_new("student.elf");

    if (!astro)
        goto failure;

    if (!stub_setup(astro, NULL, "stubby", stubby))
        goto failure;

    if (!stub_setup(astro, NULL, "backtrace", backtrace))
        goto failure;

    for (uint64_t i = 0; i <= 20; i++) {
        uint64_t ret;
        if (!call_function(astro, &ret, 1, "fib", i))
            goto failure;

        printf("fib(%lu): %lu\n", i, ret);
    }

    printf("\nnow testing stub...\n");
    if (!call_function(astro, NULL, 0, "asdf"))
        goto failure;

    astro_free(astro);
    return 0;

    failure:
    astro_free(astro);
    return 1;
}
