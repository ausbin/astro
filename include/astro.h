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
extern void astro_print_err(FILE *outfp, const char *indent,
                            const astro_err_t *astro_err);
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
typedef struct {
    uint64_t addr;
    uint64_t size;
} astro_heap_block_t;

struct astro_heap_iterator {
    // pointer to internal block
    const struct _astro_heap_block *next;
    // memory used for block user toys around with
    astro_heap_block_t block_mem;
};

typedef struct astro_heap_iterator astro_heap_iterator_t;

// Use this instead of a bool to make test code more readable
// (The malloc grader has a bunch of trues and falses and students find
//  it confusing)
typedef enum {
    NOT_FREEABLE,
    FREEABLE
} freeable_t;

typedef enum {
    UNACCESSIBLE,
    READABLE,
    WRITABLE
} accessible_t;

extern const astro_err_t *astro_read_mem(astro_t *astro, uint64_t addr,
                                         size_t size, void *out);
extern const astro_err_t *astro_write_mem(astro_t *astro, uint64_t addr,
                                          size_t size, const void *data);
extern bool astro_is_freed_block(astro_t *astro, uint64_t addr);
extern bool astro_is_malloced_block(astro_t *astro, uint64_t addr);
extern bool astro_is_stack_pointer(astro_t *astro, uint64_t addr);
extern bool astro_is_rw_static_pointer(astro_t *astro, uint64_t addr);
extern bool astro_is_ro_static_pointer(astro_t *astro, uint64_t addr);
extern const astro_err_t *astro_malloced_block_size(astro_t *astro,
                                                    uint64_t addr,
                                                    size_t *out);
extern void astro_heap_iterate(astro_t *astro, astro_heap_iterator_t *iter_mem);
extern const astro_heap_block_t *astro_heap_iterate_next(
        astro_heap_iterator_t *iter_mem);
extern void astro_set_mallocs_until_fail(astro_t *astro,
                                         int mallocs_until_fail);
const astro_err_t *astro_malloc(astro_t *astro, uint64_t size,
                                accessible_t accessible, freeable_t freeable,
                                uint64_t *addr_out);

// gdb.c
#define ASTRO_GDB_PORT_NUMBER 6969

extern const astro_err_t *astro_host_gdb_server(astro_t *astro);
extern const astro_err_t *astro_close_gdb_server(astro_t *astro);

#endif
