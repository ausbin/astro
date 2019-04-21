#include <stdio.h>
#include <stdlib.h>
#include "defs.h"

static void noop_code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)uc;
    (void)address;
    (void)size;
    (void)user_data;
}

static bool handle_segfault(uc_engine *uc, uc_mem_type type, uint64_t address,
                            int size, int64_t value, void *user_data) {
    (void)uc;
    (void)value;

    astro_t *astro = user_data;

    if (is_access_within_stack_growth_region(astro, address, size)) {
        grow_stack(astro);
        return true;
    } else {
        const char *access_name;
        switch (type) {
            case UC_MEM_READ_UNMAPPED:
            case UC_MEM_READ_PROT:
                access_name = "read";
                break;

            case UC_MEM_WRITE_UNMAPPED:
            case UC_MEM_WRITE_PROT:
                access_name = "write";
                break;

            case UC_MEM_FETCH_UNMAPPED:
            case UC_MEM_FETCH_PROT:
                access_name = "jump";
                break;

            default:
                // Should not be reachable
                access_name = "access";
        }

        fprintf(stderr, "\nSegmentation Fault\n");
        fprintf(stderr, "  invalid %s to address 0x%lx of size %d bytes\n\n",
                access_name, address, size);
        astro_print_backtrace(astro);
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

    uc_hook hh;

    uc_cb_eventmem_t segfault_cb = handle_segfault;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_MEM_INVALID,
                          FP2VOID(segfault_cb), astro, MIN_ADDR, MAX_ADDR)) {
        fprintf(stderr, "uc_hook_add segfault handler: %s\n", uc_strerror(err));
        goto failure;
    }

    // HACK: To get %rip set properly in the segfault handler, add a
    //       code hook. For some reason this works:
    //       https://github.com/unicorn-engine/unicorn/issues/534#issuecomment-241238875
    //       This results in about a 2x runtime, which is kinda brutal
    uc_cb_hookcode_t code_cb = noop_code_hook;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_CODE,
                          FP2VOID(code_cb), astro, MIN_ADDR, MAX_ADDR)) {
        fprintf(stderr, "uc_hook_add hack segfault handler: %s\n", uc_strerror(err));
        return false;
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
