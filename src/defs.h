#ifndef DEFS_H
#define DEFS_H

#include <unicorn/unicorn.h>
#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include "astro.h"

#define MIN_ADDR 0x0000000000000000UL
#define MAX_ADDR 0xffffffffffffffffUL

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
struct astro {
    FILE *binfp;
    Elf *elf;
    Dwarf *dwarf;
    uc_engine *uc;
    mem_ctx_t mem_ctx;
};

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

// The symbol defined in student.ld as marking the end of the student program
#define HEAP_START_SYMBOL "__heap_start"

extern int mem_ctx_setup(astro_t *astro);
extern void mem_ctx_cleanup(astro_t *astro);
extern int is_access_within_stack_growth_region(astro_t *astro, uint64_t addr,
                                                uint64_t size);
extern int grow_stack(astro_t *astro);

extern const char four_kb_of_zeros[0x1000];
extern char four_kb_of_uninit[0x1000];

#endif
