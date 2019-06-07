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

    if (astro_is_access_within_stack_growth_region(astro, address, size)) {
        astro_grow_stack(astro);
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

        astro->exec_err = astro_errorf(astro,
                                       "Segmentation Fault: invalid %s to "
                                       "address 0x%lx of size %d bytes",
                                       access_name, address, size);
        return false;
    }
}

const astro_err_t *astro_new(const char *elf_filename, astro_t **astro_out) {
    const astro_err_t *astro_err = NULL;
    static const astro_err_t oom_err = {.msg = "calloc: Out of Memory",
                                        .backtrace_len = 0,
                                        .backtrace = NULL};

    astro_t *astro = calloc(1, sizeof (astro_t));
    if (!astro) {
        astro_err = &oom_err;
        goto failure;
    }

    astro->sim_state = ASTRO_SIM_NO;

    // No message memory has been used yet, so point the next pointer to
    // the beginning of it
    astro->msg_mem_next = astro->msg_mem;

    if (astro_err = astro_open_elf(astro, elf_filename, &astro->binfp,
                                   &astro->elf, &astro->dwarf))
        goto failure;

    uc_err err;
    if (err = uc_open(UC_ARCH_X86, UC_MODE_64, &astro->uc)) {
        astro_err = astro_uc_perror(astro, "uc_open", err);
        goto failure;
    }

    uc_hook hh;

    uc_cb_eventmem_t segfault_cb = handle_segfault;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_MEM_INVALID,
                          FP2VOID(segfault_cb), astro, MIN_ADDR, MAX_ADDR)) {
        astro_err = astro_uc_perror(astro, "uc_hook_add segfault handler", err);
        goto failure;
    }

    // HACK: To get %rip set properly in the segfault handler, add a
    //       code hook. For some reason this works:
    //       https://github.com/unicorn-engine/unicorn/issues/534#issuecomment-241238875
    //       This results in about a 2x runtime, which is kinda brutal
    uc_cb_hookcode_t code_cb = noop_code_hook;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_CODE,
                          FP2VOID(code_cb), astro, MIN_ADDR, MAX_ADDR)) {
        astro_err = astro_uc_perror(astro, "uc_hook_add hack segfault handler", err);
        return false;
    }

    if (astro_err = astro_load_sections(astro))
        goto failure;

    if (astro_err = astro_mem_ctx_setup(astro))
        goto failure;

    *astro_out = astro;
    return NULL;

    failure:
    *astro_out = astro;
    return astro_err;
}

void astro_free(astro_t *astro) {
    if (astro) {
        astro_mem_ctx_cleanup(astro);
        if (astro->dwarf) dwarf_end(astro->dwarf);
        if (astro->elf) elf_end(astro->elf);
        if (astro->binfp) fclose(astro->binfp);
        if (astro->uc) uc_close(astro->uc);
        free(astro);
    }
}
