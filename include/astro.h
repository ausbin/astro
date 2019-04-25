#ifndef ASTRO_H
#define ASTRO_H

#include <stdint.h>
#include <stddef.h>

typedef struct astro astro_t;

// astro.c
extern astro_t *astro_new(const char *elf_filename);
extern void astro_free(astro_t *astro);

// function.c
typedef void (*astro_stub_impl_t)(astro_t *astro, void *user_data);

extern int astro_call_function(astro_t *astro, uint64_t *ret, size_t n,
                               const char *name, ...);
extern int astro_print_backtrace(astro_t *astro);
extern int astro_stub_print_backtrace(astro_t *astro);
extern int astro_stub_setup(astro_t *astro, void *user_data, const char *name,
                            astro_stub_impl_t impl);
extern int astro_stub_arg(astro_t *astro, size_t idx, uint64_t *arg_out);
extern int astro_stub_ret(astro_t *astro, uint64_t retval);
extern void astro_stub_die(astro_t *astro);

#endif
