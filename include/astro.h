#ifndef ASTRO_H
#define ASTRO_H

#include <stdbool.h>
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
    bool backtrace_truncated;
    const astro_bt_t *backtrace;
} astro_err_t;

// astro.c
extern const astro_err_t *astro_new(const char *elf_filename, astro_t **astro_out);
extern void astro_free(astro_t *astro);

// err.c
extern const astro_err_t *astro_errorf(astro_t *astro, const char *fmt, ...);
extern const astro_err_t *astro_perror(astro_t *astro, const char *s);
extern void astro_print_err(FILE *outfp, const astro_err_t *astro_err);
extern const astro_err_t *astro_errdup(const astro_err_t *astro_err);
extern void astro_escape_str(const char *in, char *out);

// function.c
typedef void (*astro_stub_impl_t)(astro_t *astro, void *user_data);

extern const astro_err_t *astro_mock_func(astro_t *astro,
                                          const char *func_name,
                                          const char *mock_func_name);
extern const astro_err_t *astro_call_function(astro_t *astro, uint64_t *ret,
                                              size_t n, const char *name, ...);
extern const astro_err_t *astro_stub_setup(astro_t *astro, void *user_data,
                                           const char *name,
                                           astro_stub_impl_t impl);
extern const astro_err_t *astro_stub_arg(astro_t *astro, size_t idx,
                                         uint64_t *arg_out);
extern const astro_err_t *astro_stub_ret(astro_t *astro, uint64_t retval);
extern void astro_stub_die(astro_t *astro, const astro_err_t *astro_err);

// mem.c
extern const astro_err_t *astro_read_mem(astro_t *astro, uint64_t addr,
                                         size_t size, uint64_t *out);
extern bool astro_is_freed_block(astro_t *astro, uint64_t addr);
extern bool astro_is_malloced_block(astro_t *astro, uint64_t addr);
extern const astro_err_t *astro_malloced_block_size(astro_t *astro,
                                                    uint64_t addr,
                                                    size_t *out);


#endif
