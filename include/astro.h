#ifndef ASTRO_H
#define ASTRO_H

#include <stdint.h>
#include <stddef.h>

typedef struct astro astro_t;

typedef struct {
    const char *file;
    const char *function;
    int line;
} astro_bt_t;

typedef struct astro_err {
    const char *msg;
    size_t backtrace_len;
    const astro_bt_t *backtrace;
} astro_err_t;

// astro.c
extern const astro_err_t *astro_new(const char *elf_filename, astro_t **astro_out);
extern void astro_free(astro_t *astro);

// err.c
extern void astro_print_err(FILE *outfp, const astro_err_t *astro_err);

// function.c
typedef void (*astro_stub_impl_t)(astro_t *astro, void *user_data);

extern const astro_err_t *astro_call_function(astro_t *astro, uint64_t *ret,
                                              size_t n, const char *name, ...);
extern const astro_err_t *astro_print_backtrace(astro_t *astro);
extern const astro_err_t *astro_stub_print_backtrace(astro_t *astro);
extern const astro_err_t *astro_stub_setup(astro_t *astro, void *user_data,
                                           const char *name,
                                           astro_stub_impl_t impl);
extern const astro_err_t *astro_stub_arg(astro_t *astro, size_t idx,
                                         uint64_t *arg_out);
extern const astro_err_t *astro_stub_ret(astro_t *astro, uint64_t retval);
extern void astro_stub_die(astro_t *astro, const astro_err_t *astro_err);

#endif
