#include <stdio.h>
#include <stdlib.h>
#include "defs.h"

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
