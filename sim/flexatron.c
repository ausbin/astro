#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include "symb.h"

#define START_ADDR 0x3000

int main(void) {
    uc_engine *uc;
    uc_err err;

    FILE *symbfp = fopen("student.sym", "r");
    if (!symbfp) {
        perror("fopen");
        return 1;
    }

    symb *sym = symb_load(symbfp);
    fclose(symbfp);

    if (!sym) {
        return 1;
    }

    if (err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc)) {
        fprintf(stderr, "uc_open: %s\n", uc_strerror(err));
        return 1;
    }

    char *binbuf = NULL;
    FILE *binfp = fopen("student.bin", "r");
    if (!binfp) {
        perror("fopen");
        goto failure;
    }

    static const char *const sections[] = {"text", "data", "bss"};

    for (unsigned int i = 0; i < sizeof sections / sizeof *sections; i++) {
        symb_section *s = symb_get_section(sym, sections[i]);
        if (!s) {
            fprintf(stderr, "missing section `%s'\n", sections[i]);
            goto failure;
        }

        uint32_t perms;

        if (!strcmp(s->name, "text"))
            perms = UC_PROT_READ | UC_PROT_EXEC;
        else if (!strcmp(s->name, "data") || !strcmp(s->name, "bss"))
            perms = UC_PROT_READ | UC_PROT_WRITE;
        else {
            fprintf(stderr, "unrecognized section `%s'\n", s->name);
            goto failure;
        }

        int length_rounded = (s->length + 0xFFF) & ~0xFFF;

        if (err = uc_mem_map(uc, s->start_addr, length_rounded, perms)) {
            fprintf(stderr, "uc_mem_map: %s\n", uc_strerror(err));
            goto failure;
        }

        char *new_binbuf = realloc(binbuf, length_rounded);
        if (!new_binbuf) {
            perror("realloc");
            goto failure;
        }
        binbuf = new_binbuf;

        // Zero out rest of section so we behave deterministically
        memset(binbuf + s->length, 0, length_rounded - s->length);

        if (!strcmp(s->name, "bss")) {
            memset(binbuf, 0, s->length);
        } else {
            if (fseek(binfp, s->start_addr - START_ADDR, SEEK_SET) < 0) {
                perror("fseek");
                goto failure;
            }

            if (fread(binbuf, 1, s->length, binfp) < s->length) {
                if (feof(binfp)) {
                    fprintf(stderr, "fread: short read\n");
                } else {
                    perror("fread");
                }
                goto failure;
            }
        }

        if (err = uc_mem_write(uc, s->start_addr, binbuf, length_rounded)) {
            fprintf(stderr, "uc_mem_write: %s\n", uc_strerror(err));
            goto failure;
        }
    }

    // TODO:
    // 1. start at the address of the function being tested
    // 2. add heap to linker script, map accordingly
    // 3. add stack to linker script, map accordingly
    if (err = uc_emu_start(uc, 0x32f1, 0, 0, 0)) {
        fprintf(stderr, "uc_emu_start: %s\n", uc_strerror(err));
        goto failure;
    }

    free(binbuf);
    fclose(binfp);
    symb_free(sym);
    uc_close(uc);

    return 0;

    failure:
    free(binbuf);
    fclose(binfp);
    symb_free(sym);
    uc_close(uc);

    return 1;
}
