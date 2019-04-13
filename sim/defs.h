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

// mem.c
#define ROUND_TO_4K(size) (((size) + 0xfff) & ~0xfff)

// (exclusive) high end of stack
#define STACK_HIGH 0x800000000000

// Protected padding on each side of block
#define HEAP_BLOCK_PADDING 32

typedef struct heap_block {
    // pointer to beginning of padding
    uint64_t addr;
    // does not include padding
    uint64_t size;
    int alloced;
    struct heap_block *next;
    uc_hook access_hook;
} heap_block_t;

typedef struct {
    uint64_t heap_start;
    uint64_t heap_end;
    // min mapped stack address
    uint64_t stack_start;
    // max mapped stack address + 1
    uint64_t stack_end;
    uc_hook stack_hook;
    heap_block_t *heap_blocks;
} mem_ctx_t;

mem_ctx_t *mem_ctx_new(uc_engine *uc, Elf *elf);

// function.c
typedef void (*stub_impl_t)(uc_engine *uc, Elf *elf, void *user_data);

extern int call_function(uc_engine *uc, Elf *elf, uint64_t stack_bottom,
                  uint64_t *ret, size_t n, const char *name, ...);
extern int stub_setup(uc_engine *uc, Elf *elf, void *user_data, const char *name,
                      stub_impl_t impl);
extern int stub_arg(uc_engine *uc, size_t idx, uint64_t *arg_out);
extern int stub_ret(uc_engine *uc, uint64_t retval);
extern void stub_die(uc_engine *uc);

#endif
