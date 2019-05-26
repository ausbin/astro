#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"

const astro_err_t *astro_errorf(astro_t *astro, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    size_t n = vsnprintf(astro->msg_mem, sizeof astro->msg_mem, fmt, ap);
    if (n == sizeof astro->msg_mem) {
        // put "..." if truncated
        for (int i = 0; i < 3; i++)
            astro->msg_mem[n - 2 - i] = '.';
        astro->msg_mem[n - 1] = '\0';
    }

    va_end(ap);

    astro->err_mem.msg = astro->msg_mem;
    astro->err_mem.backtrace_len = 0;
    astro->err_mem.backtrace = NULL;
    return &astro->err_mem;
}

const astro_err_t *astro_perror(astro_t *astro, const char *s) {
    return astro_errorf(astro, "%s: %s", s, strerror(errno));
}

const astro_err_t *astro_uc_perror(astro_t *astro, const char *s, uc_err err) {
    return astro_errorf(astro, "%s: %s", s, uc_strerror(err));
}

const astro_err_t *astro_elf_perror(astro_t *astro, const char *s) {
    return astro_errorf(astro, "%s: %s", s, elf_errmsg(-1));
}

const astro_err_t *astro_dwarf_perror(astro_t *astro, const char *s) {
    return astro_errorf(astro, "%s: %s", s, dwarf_errmsg(-1));
}

void astro_print_err(FILE *outfp, const astro_err_t *astro_err) {
    fprintf(outfp, "ERROR: %s\n", astro_err->msg);
    // TODO: print backtrace
}
