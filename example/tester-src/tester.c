#include <stdio.h>
#include <stdlib.h>
#include "astro.h"

static void backtrace(astro_t *astro, void *user_data) {
    (void)user_data;

    if (!astro_stub_print_backtrace(astro))
        goto failure;

    return;

    failure:
    astro_stub_die(astro);
}

int main(void) {
    astro_t *astro = astro_new("student.elf");

    if (!astro)
        goto failure;

    if (!astro_stub_setup(astro, NULL, "__backtrace", backtrace))
        goto failure;

    for (uint64_t i = 0; i <= 20; i++) {
        uint64_t ret;
        if (!astro_call_function(astro, &ret, 1, "fib", i))
            goto failure;

        printf("fib(%lu): %lu\n", i, ret);
    }

    printf("\nnow testing stub...\n");
    if (!astro_call_function(astro, NULL, 0, "asdf"))
        goto failure;

    astro_free(astro);
    return 0;

    failure:
    astro_free(astro);
    return 1;
}
