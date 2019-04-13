#include <stdio.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include <libelf.h>
#include "defs.h"

static void stubby(uc_engine *uc, Elf *elf, void *user_data) {
    (void)user_data;
    (void)elf;

    uint64_t n;
    if (!stub_arg(uc, 0, &n))
        return;

    printf("stubby called! n = 0x%lx\n", n);
}

int main(void) {
    uc_engine *uc;
    uc_err err;

    FILE *binfp = NULL;
    Elf *elf = NULL;
    mem_ctx_t *mem_ctx = NULL;

    if (!open_elf("student.elf", &binfp, &elf))
        goto failure;

    if (err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc)) {
        fprintf(stderr, "uc_open: %s\n", uc_strerror(err));
        goto failure;
    }

    // Set 4K of uninitialized memory to 0x69s
    // (reused to initialize memory deterministically)
    mem_uninit_init();

    if (!load_sections(uc, elf))
        goto failure;

    mem_ctx = mem_ctx_new(uc, elf);
    if (!mem_ctx)
        goto failure;

    if (!stub_setup(uc, elf, NULL, "stubby", stubby))
        goto failure;

    for (uint64_t i = 0; i <= 20; i++) {
        uint64_t ret;
        if (!call_function(uc, elf, mem_ctx->stack_end, &ret, 1,
                           "fib", i))
            goto failure;

        printf("fib(%lu): %lu\n", i, ret);
    }

    printf("\nnow testing stub...\n");
    if (!call_function(uc, elf, mem_ctx->stack_end, NULL, 0, "asdf"))
        goto failure;

    mem_ctx_free(mem_ctx);
    elf_end(elf);
    fclose(binfp);
    uc_close(uc);

    return 0;

    failure:
    if (mem_ctx) mem_ctx_free(mem_ctx);
    if (elf) elf_end(elf);
    if (binfp) fclose(binfp);
    uc_close(uc);

    return 1;
}
