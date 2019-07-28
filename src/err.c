#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"

const astro_err_t *astro_errorf(astro_t *astro, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    size_t max = astro->msg_mem + sizeof astro->msg_mem - astro->msg_mem_next;
    size_t n = vsnprintf(astro->msg_mem_next, max, fmt, ap);
    if (n == max && n >= 3) {
        // put "..." if truncated
        for (int i = 0; i < 3; i++)
            astro->msg_mem_next[n - 2 - i] = '.';
        astro->msg_mem_next[n - 1] = '\0';
    }

    va_end(ap);

    astro->err_mem.msg = astro->msg_mem_next;
    // +1 accounts for null terminator
    astro->msg_mem_next += n + 1;

    const astro_err_t *astro_err;
    if (astro_err = astro_make_backtrace(
            astro, &astro->err_mem.backtrace, &astro->err_mem.backtrace_len,
            &astro->err_mem.backtrace_truncated)) {
        return astro_err;
    }

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

void astro_print_err(FILE *outfp, const char *indent,
                     const astro_err_t *astro_err) {
    fprintf(outfp, "%sERROR: %s\n", indent, astro_err->msg);

    for (unsigned int i = 0; i < astro_err->backtrace_len; i++) {
        const astro_bt_t *frame = &astro_err->backtrace[i];
        fprintf(outfp, "%s%s%s() at %s:%d\n", indent, indent, frame->function,
                                              frame->file, frame->line);
    }
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
    result->backtrace_truncated = astro_err->backtrace_truncated;

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

        result->backtrace = bt;
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
    astro_print_err(stderr, "\t", astro_err);

    static const astro_err_t oom_err = {.msg = "malloc for astro_err_t copy: "
                                               "Out of Memory",
                                        .backtrace_len = 0,
                                        .backtrace = NULL};
    return &oom_err;
}

const char *astro_intern_str(astro_t *astro, const char *src) {
    size_t size = strlen(src) + 1;
    size_t max = astro->msg_mem + sizeof astro->msg_mem - astro->msg_mem_next;
    if (size > max) {
        return "??";
    } else {
        char *ret = astro->msg_mem_next;
        strcpy(ret, src);
        astro->msg_mem_next += size;
        return ret;
    }
}

void astro_escape_str(const char *in, char *out) {
    if (!in || !out)
        return;

    while (*in) {
        switch (*in) {
            case '\n':
            *out++ = '\\';
            *out++ = 'n';
            break;

            case '\t':
            *out++ = '\\';
            *out++ = 't';
            break;

            default:
            *out++ = *in;
        }

        in++;
    }

    *out = '\0';
}
