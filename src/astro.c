#include <stdio.h>
#include <stdlib.h>
#include "defs.h"

static void halt_hook(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data) {
    (void)uc;
    (void)address;
    (void)size;

    astro_t *astro = user_data;
    astro->halted = true;
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

    // HACK: To get %rip set properly in the segfault handler, add a
    //       code hook. For some reason this works:
    //       https://github.com/unicorn-engine/unicorn/issues/534#issuecomment-241238875
    //       This results in about a 2x runtime, which is kinda brutal
    uc_cb_hookcode_t code_cb = breakpoint_code_hook;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_CODE,
                          FP2VOID(code_cb), astro, MIN_ADDR, MAX_ADDR)) {
        astro_err = astro_uc_perror(astro, "uc_hook_add hack segfault handler", err);
        goto failure;
    }

    // Detect if we've hit a timeout
    uint64_t entry_point;
    if (astro_err = astro_get_entry_point_addr(astro, &entry_point))
        goto failure;

    uc_cb_hookcode_t halt_cb = halt_hook;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_CODE,
                          FP2VOID(halt_cb), astro, entry_point, entry_point)) {
        astro_err = astro_uc_perror(astro, "uc_hook_add entry point handler", err);
        goto failure;
    }

    if (astro_err = astro_load_sections(astro))
        goto failure;

    if (astro_err = astro_mem_ctx_setup(astro))
        goto failure;

    if (astro_err = astro_gdb_ctx_setup(astro))
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
