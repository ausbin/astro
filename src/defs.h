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

#define MIN(a, b) ((a) < (b)? (a) : (b))

// mem.c pt. 1
typedef enum {
    // Never returned to the student at all. Only blocks in this state
    // will be returned to the student so that we control how memory
    // that malloc returns a pointer to is initialized
    UNTOUCHED,
    // free()d. Will not be used again to prevent confusing behavior
    FREED,
    // returned by malloc() and not yet free()d
    MALLOCED
} heap_block_state_t;

typedef struct _astro_heap_block {
    // pointer to beginning of padding
    uint64_t addr;
    // does not include padding
    uint64_t size;
    heap_block_state_t state;
    struct _astro_heap_block *next;
    uc_hook access_hook;
} heap_block_t;

typedef struct {
    uint64_t low_addr;
    uint64_t high_addr;
} addr_range_t;

typedef struct {
    addr_range_t text_range;
    addr_range_t rodata_range;
    addr_range_t bss_range;
    addr_range_t heap_range;
    // (min mapped stack address, max mapped stack address + 1)
    addr_range_t stack_range;

    uc_hook stack_hook;
    heap_block_t *heap_blocks;
    // number of mallocs to succeed until forcing
    // malloc()/calloc()/realloc() to return NULL (regardless of actual
    // available heap space)
    int mallocs_until_fail;
} mem_ctx_t;

// function.c pt 1
typedef struct {
    const char *func_name;
    const char *mock_func_name;
} mock_func_t;

typedef struct stub {
    int valid;
    astro_t *astro;
    void *user_data;
    astro_stub_impl_t impl;
    uc_hook hook;
} stub_t;

// astro.c
enum astro_sim_state {
    // Not currently simulating student code
    ASTRO_SIM_NO,
    // Their code was being executed but encountered a runtime issue
    // (e.g., segfault)
    ASTRO_SIM_EXEC,
    // They called a stub
    // (special case of ASTRO_SIM_EXEC that is necessary because the
    //  stack/registers are in a different state when the student calls
    //  a stub versus when they cause a runtime error)
    ASTRO_SIM_STUB
};

struct astro {
    FILE *binfp;
    Elf *elf;
    Dwarf *dwarf;
    uc_engine *uc;
    mem_ctx_t mem_ctx;
    const astro_err_t *exec_err;
    enum astro_sim_state sim_state;

    // Function mocking (useful for meta-testing, that is writing tests
    // for tests to make sure astro/tester works)
    mock_func_t mock_funcs[4];
    stub_t stubs[32];

    // Pointer to unused message memory (below)
    char *msg_mem_next;

    // Pre-allocate error handling memory so that malloc()ing cannot
    // fail when handling an error
    astro_err_t err_mem;
    char msg_mem[2048];
    astro_bt_t bt_mem[64];
};

// elf.c
extern const astro_err_t *astro_open_elf(astro_t *astro, const char *filename,
                                         FILE **fp_out, Elf **elf_out,
                                         Dwarf **dwarf_out);
extern const astro_err_t *astro_get_entry_point_addr(astro_t *astro,
                                                     uint64_t *addr_out);
extern const astro_err_t *astro_load_sections(astro_t *astro);
extern int astro_get_symbol_addr(astro_t *astro, const char *needle_name,
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

extern const astro_err_t *astro_mem_ctx_setup(astro_t *astro);
extern void astro_mem_ctx_cleanup(astro_t *astro);
extern int astro_is_access_within_stack_growth_region(astro_t *astro,
                                                      uint64_t addr,
                                                      uint64_t size);
extern const astro_err_t *astro_grow_stack(astro_t *astro);

extern const char four_kb_of_zeros[0x1000];
extern char four_kb_of_uninit[0x1000];

// err.c
// Don't expose these to users since they have no business poking around
// with dependency libraries
extern const astro_err_t *astro_uc_perror(astro_t *astro, const char *s, uc_err err);
extern const astro_err_t *astro_elf_perror(astro_t *astro, const char *s);
extern const astro_err_t *astro_dwarf_perror(astro_t *astro, const char *s);
extern const char *astro_intern_str(astro_t *astro, const char *src);

// function.c
const astro_err_t *astro_make_backtrace(astro_t *astro,
                                        const astro_bt_t **bt_out,
                                        size_t *bt_len_out,
                                        bool *bt_truncated_out);

#endif
