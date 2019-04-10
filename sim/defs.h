#ifndef DEFS_H
#define DEFS_H

#include <stdint.h>
#include <unicorn/unicorn.h>
#include <libelf.h>

// Revolting hack to convert a function pointer variable to a void
// pointer. This violates C99 but Unicorn requires it, please don't
// hate.
#define FP2VOID(fp_var) (*((void **) &(fp_var)))

// astro.c
extern const char four_kb_of_zeros[0x1000];

// elf.c
extern int open_elf(const char *filename, FILE **fp_out, Elf **elf_out);
extern int get_entry_point_addr(Elf *elf, uint64_t *addr_out);
extern int load_sections(uc_engine *uc, Elf *elf);
extern int get_symbol_addr(Elf *elf, const char *needle_name, uint64_t *addr_out);

// function.c
extern int call_function(uc_engine *uc, Elf *elf, uint64_t stack_bottom,
                  uint64_t *ret, size_t n, const char *name, ...);
extern int setup_hooks(uc_engine *uc, Elf *elf);

// mem.c
// (exclusive) high end of stack
#define STACK_HIGH 0x800000000000

typedef struct {
    uint64_t heap_start;
    uint64_t heap_end;
    // min mapped stack address
    uint64_t stack_start;
    // max mapped stack address
    uint64_t stack_end;
    uc_hook stack_hook;
} mem_ctx;

mem_ctx *mem_ctx_new(uc_engine *uc, Elf *elf);

#endif
