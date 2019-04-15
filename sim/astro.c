#include <stdio.h>
#include <stdlib.h>
#include "defs.h"

static bool handle_segfault(uc_engine *uc, uc_mem_type type, uint64_t address,
                            int size, int64_t value, void *user_data) {
    (void)uc;
    (void)type;
    (void)value;

    astro_t *astro = user_data;

    if (is_access_within_stack_growth_region(astro, address, size)) {
        grow_stack(astro);
        return true;
    } else {
        fprintf(stderr, "Segmentation Fault\n");
        fprintf(stderr, "  attempted to access invalid address 0x%lx\n\n", address);
        print_backtrace(astro);
        return false;
    }
}

astro_t *astro_new(const char *elf_filename) {
    uc_err err;

    astro_t *astro = calloc(1, sizeof (astro_t));
    if (!astro) {
        perror("calloc");
        goto failure;
    }

    if (!open_elf(elf_filename, &astro->binfp, &astro->elf, &astro->dwarf))
        goto failure;

    if (err = uc_open(UC_ARCH_X86, UC_MODE_64, &astro->uc)) {
        fprintf(stderr, "uc_open: %s\n", uc_strerror(err));
        goto failure;
    }

    uc_cb_eventmem_t segfault_cb = handle_segfault;
    uc_hook hh;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_MEM_INVALID,
                          FP2VOID(segfault_cb), astro,
                          0x0000000000000000UL, 0xffffffffffffffffUL)) {
        fprintf(stderr, "uc_hook_add segfault handler: %s\n", uc_strerror(err));
        goto failure;
    }

    if (!load_sections(astro))
        goto failure;

    if (!mem_ctx_setup(astro))
        goto failure;

    return astro;

    failure:
    astro_free(astro);
    return NULL;
}

void astro_free(astro_t *astro) {
    if (astro) {
        mem_ctx_cleanup(astro);
        if (astro->dwarf) dwarf_end(astro->dwarf);
        if (astro->elf) elf_end(astro->elf);
        if (astro->binfp) fclose(astro->binfp);
        if (astro->uc) uc_close(astro->uc);
        free(astro);
    }
}
