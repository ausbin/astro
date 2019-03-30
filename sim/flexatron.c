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

        // If it's empty, don't bother trying to map since that'll fail
        // and is pointless anyway
        if (!s->length)
            continue;

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
            fprintf(stderr, "uc_mem_map section .%s: %s\n", s->name, uc_strerror(err));
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

    // Now, need to setup stack and heap -- allocate 8K for each
    // Put heap right where __heap_start is (from linker script)
    symb_symbol *heap_start = symb_get_symbol(sym, "__heap_start");
    if (!heap_start) {
        fprintf(stderr, "where is my __heap_start symbol?\n");
        goto failure;
    }
    if (err = uc_mem_map(uc, heap_start->addr, 0x2000, UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map heap: %s\n", uc_strerror(err));
        goto failure;
    }
    char *zeros = calloc(1, 0x2000);
    if (!zeros) {
        perror("calloc");
        goto failure;
    }
    if (err = uc_mem_write(uc, heap_start->addr, zeros, 0x2000)) {
        fprintf(stderr, "uc_mem_write heap: %s\n", uc_strerror(err));
        free(zeros);
        goto failure;
    }

    // Leave a 4K guard gap
    if (err = uc_mem_map(uc, heap_start->addr + 0x3000, 0x2000, UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map stack: %s\n", uc_strerror(err));
        free(zeros);
        goto failure;
    }
    if (err = uc_mem_write(uc, heap_start->addr + 0x3000, zeros, 0x2000)) {
        fprintf(stderr, "uc_mem_write stack: %s\n", uc_strerror(err));
        free(zeros);
        goto failure;
    }
    free(zeros);

    uint64_t return_address = START_ADDR;
    uint64_t stack_start = heap_start->addr + 0x5000 - 8;
    uint64_t arg = 2;

    if (err = uc_mem_write(uc, stack_start, &return_address, 8)) {
        fprintf(stderr, "uc_mem_write return address: %s\n", uc_strerror(err));
        goto failure;
    }

    if (err = uc_reg_write(uc, UC_X86_REG_RSP, &stack_start)) {
        fprintf(stderr, "uc_reg_write %%rsp: %s\n", uc_strerror(err));
        goto failure;
    }

    if (err = uc_reg_write(uc, UC_X86_REG_RDI, &arg)) {
        fprintf(stderr, "uc_reg_write %%rdi: %s\n", uc_strerror(err));
        goto failure;
    }

    arg = 1;
    if (err = uc_reg_write(uc, UC_X86_REG_RSI, &arg)) {
        fprintf(stderr, "uc_reg_write %%rsi: %s\n", uc_strerror(err));
        goto failure;
    }

    symb_symbol *func = symb_get_symbol(sym, "add_integers");
    if (!func) {
        fprintf(stderr, "where is my symbol to test?\n");
        goto failure;
    }

    if (err = uc_emu_start(uc, func->addr, 0, 0, 0)) {
        fprintf(stderr, "uc_emu_start: %s\n", uc_strerror(err));
        goto failure;
    }

    uint64_t ret;
    if (err = uc_reg_read(uc, UC_X86_REG_RAX, &ret)) {
        fprintf(stderr, "uc_reg_read %%rax: %s\n", uc_strerror(err));
        goto failure;
    }

    printf("result from emulation: %lu\n", ret);

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
