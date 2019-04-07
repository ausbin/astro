#include <stdio.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include <libelf.h>
#include "defs.h"

int main(void) {
    uc_engine *uc;
    uc_err err;

    FILE *binfp = NULL;
    Elf *elf = NULL;
    if (!open_elf("student.elf", &binfp, &elf))
        goto failure;

    if (err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc)) {
        fprintf(stderr, "uc_open: %s\n", uc_strerror(err));
        goto failure;
    }

    if (!load_sections(uc, elf))
        goto failure;

    uint64_t stack_bottom = setup_stack_heap(uc, elf);

    if (!stack_bottom)
        goto failure;

    if (!setup_hooks(uc, elf))
        goto failure;

    for (uint64_t i = 0; i <= 20; i++) {
        uint64_t ret;
        if (!call_function(uc, elf, stack_bottom, &ret, 1,
                           "fib", i))
            goto failure;

        printf("fib(%lu): %lu\n", i, ret);
    }

    printf("\nnow testing stub...\n");
    if (!call_function(uc, elf, stack_bottom, NULL, 0, "asdf"))
        goto failure;

    elf_end(elf);
    fclose(binfp);
    uc_close(uc);

    return 0;

    failure:
    if (elf) elf_end(elf);
    if (binfp) fclose(binfp);
    uc_close(uc);

    return 1;
}
