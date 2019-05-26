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

const astro_err_t *astro_errdup(const astro_err_t *astro_err) {
    // duplicate of NULL is NULL
    if (!astro_err)
        return NULL;

    astro_err_t *result = calloc(1, sizeof (astro_err_t));
    if (!result) {
        goto failure;
    }

    result->backtrace_len = astro_err->backtrace_len;

    if (astro_err->msg) {
        char *msg = malloc(strlen(astro_err->msg) + 1);
        if (!msg) {
            goto failure;
        }
        strcpy(msg, astro_err->msg);
        result->msg = msg;
    }

    if (astro_err->backtrace) {
        astro_bt_t *bt = malloc(astro_err->backtrace_len * sizeof (astro_bt_t));
        if (!bt) {
            goto failure;
        }
        memcpy(bt, astro_err->backtrace,
               astro_err->backtrace_len * sizeof (astro_bt_t));

        for (unsigned int i = 0; i < astro_err->backtrace_len; i++) {
            char *file = malloc(strlen(bt[i].file) + 1);
            if (!file) {
                goto bt_failure;
            }
            strcpy(file, bt[i].file);
            bt[i].file = file;

            char *function = malloc(strlen(bt[i].function) + 1);
            if (!file) {
                free(file);
                goto bt_failure;
            }
            strcpy(function, bt[i].function);
            bt[i].function = function;

            continue;

            bt_failure:
            for (unsigned int j = 0; j < i; j++) {
                // the frame struct has const qualifiers on these guys,
                // but we created them with a malloc, so cast them away
                free((char *) bt[j].file);
                free((char *) bt[j].function);
            }
            free(bt);
            goto failure;
        }
    }

    return result;

    failure:
    if (result) {
        // We made this string with a malloc, so it's safe to free
        if (result->msg) free((char *) result->msg);
        free(result);
    }

    // Log the original error so we're not just throwing it away
    fprintf(stderr, "allocating a copy of the following astro_err_t failed: ");
    astro_print_err(stderr, astro_err);

    static const astro_err_t oom_err = {.msg = "malloc for astro_err_t copy: "
                                               "Out of Memory",
                                        .backtrace_len = 0,
                                        .backtrace = NULL};
    return &oom_err;
}
