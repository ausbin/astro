#ifndef DEFS_H
#define DEFS_H

#include <stdint.h>
#include <unicorn/unicorn.h>
#include <libelf.h>
#include <elfutils/libdw.h>

// Revolting hack to convert a function pointer variable to a void
// pointer. This violates C99 but Unicorn requires it, please don't
// hate.
#define FP2VOID(fp_var) (*((void **) &(fp_var)))

// mem.c pt. 1
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

// astro.c
typedef struct {
    FILE *binfp;
    Elf *elf;
    Dwarf *dwarf;
    uc_engine *uc;
    mem_ctx_t mem_ctx;
} astro_t;

extern astro_t *astro_new(const char *elf_filename);
extern void astro_free(astro_t *astro);

// elf.c
extern int open_elf(const char *filename, FILE **fp_out, Elf **elf_out,
                    Dwarf **dwarf_out);
extern int get_entry_point_addr(astro_t *astro, uint64_t *addr_out);
extern int load_sections(astro_t *astro);
extern int get_symbol_addr(astro_t *astro, const char *needle_name,
                           uint64_t *addr_out);

// mem.c pt. 2
#define ROUND_TO_4K(size) (((size) + 0xfff) & ~0xfff)

// What to fill "uninitialized" memory with
// Why not zero? Student code should break if they assume memory is
// zeroed
#define UNINIT_BYTE 0x69

// (exclusive) high end of stack
#define STACK_HIGH 0x800000000000

// Protected padding on each side of block
#define HEAP_BLOCK_PADDING 32

extern int mem_ctx_setup(astro_t *astro);
extern void mem_ctx_cleanup(astro_t *astro);

extern const char four_kb_of_zeros[0x1000];
extern char four_kb_of_uninit[0x1000];

// function.c
typedef void (*stub_impl_t)(astro_t *astro, void *user_data);

extern int call_function(astro_t *astro, uint64_t *ret, size_t n,
                         const char *name, ...);
extern int stub_setup(astro_t *astro, void *user_data, const char *name,
                      stub_impl_t impl);
extern int stub_arg(astro_t *astro, size_t idx, uint64_t *arg_out);
extern int stub_ret(astro_t *astro, uint64_t retval);
extern void stub_die(astro_t *astro);

#endif
