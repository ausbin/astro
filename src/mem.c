// Memory management

#include <string.h>
#include "defs.h"

const char four_kb_of_zeros[0x1000];
char four_kb_of_uninit[0x1000];

static void mem_uninit_init(void) {
    memset(four_kb_of_uninit, UNINIT_BYTE, 0x1000);
}

const astro_err_t *astro_grow_stack(astro_t *astro) {
    const astro_err_t *astro_err = NULL;
    uc_err err;

    astro->mem_ctx.stack_range.low_addr -= 0x1000;

    if (err = uc_mem_map(astro->uc, astro->mem_ctx.stack_range.low_addr,
                         0x1000, UC_PROT_READ | UC_PROT_WRITE)) {
        astro_err = astro_uc_perror(astro, "uc_mem_map stack", err);
        goto failure;
    }
    if (err = uc_mem_write(astro->uc, astro->mem_ctx.stack_range.low_addr,
                           four_kb_of_uninit, 0x1000)) {
        astro_err = astro_uc_perror(astro, "uc_mem_write stack", err);
        goto failure;
    }

    return NULL;

    failure:
    return astro_err;
}

// Called by the segfault handler so as not to throw unnecessary
// segfaults for stack growth
int astro_is_access_within_stack_growth_region(astro_t *astro,
                                               uint64_t addr,
                                               uint64_t size) {
    uint64_t end_addr = addr + size - 1;
    return addr >= astro->mem_ctx.stack_range.low_addr - 0x1000 &&
           addr < astro->mem_ctx.stack_range.low_addr &&
           end_addr >= astro->mem_ctx.stack_range.low_addr - 0x1000 &&
           end_addr < astro->mem_ctx.stack_range.low_addr;
}

// sbrk(), basically
static const astro_err_t *mem_ctx_grow_heap(astro_t *astro, uint64_t size,
                                            heap_block_t **block_out) {
    const astro_err_t *astro_err;
    uc_err err;
    heap_block_t *new_block = NULL;
    uint64_t size_rounded = ROUND_TO_4K(size + 2*HEAP_BLOCK_PADDING);

    if (err = uc_mem_map(astro->uc, astro->mem_ctx.heap_range.high_addr,
                         size_rounded, UC_PROT_READ | UC_PROT_WRITE)) {
        astro_err = astro_uc_perror(astro, "uc_mem_map heap space", err);
        goto failure;
    }

    // Initialize memory
    for (uint64_t a = astro->mem_ctx.heap_range.high_addr;
         a < astro->mem_ctx.heap_range.high_addr + size_rounded;
         a += 0x1000) {
        if (err = uc_mem_write(astro->uc, a, four_kb_of_uninit, 0x1000)) {
            astro_err = astro_uc_perror(astro,
                                        "uc_mem_write initialize heap space",
                                        err);
            goto failure;
        }
    }

    new_block = malloc(sizeof (heap_block_t));
    if (!new_block) {
        astro_err = astro_perror(astro, "malloc");
        goto failure;
    }

    new_block->addr = astro->mem_ctx.heap_range.high_addr;
    new_block->size = size_rounded - 2*HEAP_BLOCK_PADDING;
    new_block->state = UNTOUCHED;
    new_block->next = NULL;

    heap_block_t *tail = astro->mem_ctx.heap_blocks;
    while (tail && tail->next)
        tail = tail->next;
    if (!tail)
        astro->mem_ctx.heap_blocks = new_block;
    else
        tail->next = new_block;

    astro->mem_ctx.heap_range.high_addr += size_rounded;

    *block_out = new_block;
    return NULL;

    failure:
    free(new_block);
    return astro_err;
}

static const astro_err_t *mem_ctx_heap_malloc(astro_t *astro, uint64_t size,
                                              uint64_t *addr_out) {
    const astro_err_t *astro_err;
    heap_block_t *exact_match = NULL;
    heap_block_t *split_match = NULL;

    for (heap_block_t *b = astro->mem_ctx.heap_blocks;
         b && !exact_match && !split_match;
         b = b->next)
        if (b->state == UNTOUCHED && b->size == size)
            exact_match = b;
        else if (b->state == UNTOUCHED &&
                 b->size >= size + 2*HEAP_BLOCK_PADDING + 1)
            split_match = b;

    // Need to map some more space
    if (!exact_match && !split_match) {
        heap_block_t *new_block;
        if (astro_err = mem_ctx_grow_heap(astro, size, &new_block))
            goto failure;

        if (new_block->size == size)
            exact_match = new_block;
        else
            split_match = new_block;
    }

    heap_block_t *result;
    if (exact_match) {
        result = exact_match;
    } else {
        // Need to perform a split
        result = malloc(sizeof (heap_block_t));
        if (!result) {
            astro_err = astro_perror(astro, "malloc");
            goto failure;
        }

        // Fix next pointers
        result->next = split_match->next;
        split_match->next = result;

        // Fix sizes
        result->size = size;
        split_match->size -= 2*HEAP_BLOCK_PADDING + size;

        // Fix start address
        result->addr = split_match->addr + split_match->size + 2*HEAP_BLOCK_PADDING;
    }

    result->state = MALLOCED;
    *addr_out = result->addr + HEAP_BLOCK_PADDING;

    return NULL;

    failure:
    *addr_out = 0;
    return astro_err;
}

static void mem_ctx_heap_find_block(astro_t *astro, uint64_t addr,
                                    heap_block_t **prev_out,
                                    heap_block_t **match_out) {
    heap_block_t *prev = NULL;
    heap_block_t *match = NULL;

    for (heap_block_t *b = astro->mem_ctx.heap_blocks;
         !match && b;
         b = b->next)
        if (b->addr + HEAP_BLOCK_PADDING == addr)
            match = b;
        else
            prev = b;

    if (prev_out)
        *prev_out = match? prev : NULL;
    if (match_out)
        *match_out = match;
}

static const astro_err_t *mem_ctx_heap_free(astro_t *astro, uint64_t addr) {
    const astro_err_t *astro_err;
    heap_block_t *prev = NULL;
    heap_block_t *match = NULL;

    mem_ctx_heap_find_block(astro, addr, &prev, &match);

    if (!match) {
        // TODO: this error message is garbage
        astro_err = astro_errorf(astro, "free()ing garbage pointer 0x%lx!",
                                 addr);
        goto failure;
    }

    if (match->state == FREED) {
        // TODO: this error message is garbage
        // TODO: not necessarily a double free
        astro_err = astro_errorf(astro, "Double free() of address 0x%lx!",
                                 addr);
        goto failure;
    } else if (match->state == UNTOUCHED) {
        astro_err = astro_errorf(astro, "free()ing a pointer 0x%lx not yet "
                                        "returned by malloc()! Are you a time "
                                        "traveller?", addr);
        goto failure;
    }

    match->state = FREED;

    // Don't attempt merges because we don't want block to move around
    // on free(). For example, if the student returns a free()d block,
    // we need to know it's freed

    return NULL;

    failure:
    return astro_err;
}

// TODO: Will these error messages say malloc()? Is that too confusing?
static const astro_err_t *mem_ctx_heap_calloc(astro_t *astro,
                                              uint64_t nmemb,
                                              uint64_t size,
                                              uint64_t *addr_out) {
    const astro_err_t *astro_err;
    uc_err err;
    uint64_t total_size = nmemb * size;

    uint64_t addr = 0;
    if (astro_err = mem_ctx_heap_malloc(astro, total_size, &addr))
        goto failure;

    // Zero out the block 4K at a time
    for (uint64_t a = addr; a < addr + total_size; a += 0x1000) {
        uint64_t n = MIN(addr + total_size - a, 0x1000);

        if (err = uc_mem_write(astro->uc, a, four_kb_of_zeros, n)) {
            astro_err = astro_uc_perror(astro, "uc_mem_write calloc", err);
            goto failure;
        }
    }

    *addr_out = addr;
    return NULL;

    failure:
    *addr_out = 0;
    return astro_err;
}

// TODO: Will these error messages say malloc()/free()? Is that too confusing?
static const astro_err_t *mem_ctx_heap_realloc(astro_t *astro,
                                               uint64_t ptr,
                                               uint64_t size,
                                               uint64_t *addr_out) {
    const astro_err_t *astro_err;
    uc_err err;
    heap_block_t *match = NULL;
    uint64_t existing_size = 0;

    if (ptr) {
        mem_ctx_heap_find_block(astro, ptr, NULL, &match);

        if (!match) {
            // TODO: this error message is garbage
            astro_err = astro_errorf(astro,
                                     "realloc()ing garbage pointer 0x%lx!",
                                     ptr);
            goto failure;
        }

        if (match->state == FREED) {
            // TODO: this error message is semi garbage
            astro_err = astro_errorf(astro,
                                     "realloc() called on free block 0x%lx! "
                                     "Do not free() a pointer before passing "
                                     "it to ralloc()!\n", ptr);
            goto failure;
        } else if (match->state == UNTOUCHED) {
            astro_err = astro_errorf(astro, "realloc()ing a pointer 0x%lx not "
                                            "yet returned by malloc()! Are "
                                            "you a time traveller?\n", ptr);
            goto failure;
        }

        existing_size = match->size;
    }

    uint64_t addr;

    // return NULL if size is 0
    if (!size) {
        addr = 0;
    // Else provided they provided an existing pointer, we want to malloc the
    // new size and copy contents over
    } else if (ptr) {
        if (!mem_ctx_heap_malloc(astro, size, &addr))
            goto failure;

        uint64_t copy_size = MIN(existing_size, size);
        char *tmp_buf = malloc(MIN(0x1000, copy_size));

        if (!tmp_buf) {
            astro_err = astro_perror(astro, "malloc");
            goto failure;
        }

        // Copy 4K at a time
        for (uint64_t a = ptr; a < ptr + copy_size; a += 0x1000) {
            uint64_t n = MIN(ptr + copy_size - a, 0x1000);

            if (err = uc_mem_read(astro->uc, a, tmp_buf, n)) {
                astro_err = astro_uc_perror(astro, "uc_mem_read realloc", err);
                goto failure;
            }

            if (err = uc_mem_write(astro->uc, a, tmp_buf, n)) {
                astro_err = astro_uc_perror(astro, "uc_mem_write realloc",
                                            err);
                goto failure;
            }
        }
    }

    // If they passed an old block, free it now
    if (ptr && !mem_ctx_heap_free(astro, ptr))
        goto failure;

    *addr_out = addr;
    return NULL;

    failure:
    *addr_out = 0;
    return astro_err;
}

static void malloc_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    const astro_err_t *astro_err;

    uint64_t size;
    if (astro_err = astro_stub_arg(astro, 0, &size))
        goto failure;

    uint64_t addr = 0;
    if (astro_err = mem_ctx_heap_malloc(astro, size, &addr))
        goto failure;

    if (astro_err = astro_stub_ret(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro, astro_err);
}

static void free_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    const astro_err_t *astro_err;

    uint64_t addr;
    if (astro_err = astro_stub_arg(astro, 0, &addr))
        goto failure;

    if (astro_err = mem_ctx_heap_free(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro, astro_err);
}

static void calloc_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    const astro_err_t *astro_err;

    uint64_t nmemb;
    if (astro_err = astro_stub_arg(astro, 0, &nmemb))
        goto failure;
    uint64_t size;
    if (astro_err = astro_stub_arg(astro, 1, &size))
        goto failure;

    uint64_t addr = 0;
    if (astro_err = mem_ctx_heap_calloc(astro, nmemb, size, &addr))
        goto failure;

    if (astro_err = astro_stub_ret(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro, astro_err);
}

static void realloc_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    const astro_err_t *astro_err;

    uint64_t ptr;
    if (astro_err = astro_stub_arg(astro, 0, &ptr))
        goto failure;
    uint64_t size;
    if (astro_err = astro_stub_arg(astro, 1, &size))
        goto failure;

    uint64_t addr = 0;
    if (astro_err = mem_ctx_heap_realloc(astro, ptr, size, &addr))
        goto failure;

    if (astro_err = astro_stub_ret(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro, astro_err);
}

const astro_err_t *astro_mem_ctx_setup(astro_t *astro) {
    const astro_err_t *astro_err;

    // Set 4K of uninitialized memory to 0x69s
    // (reused to initialize memory deterministically)
    mem_uninit_init();

    // Now, need to setup stack and heap -- allocate 8K for each
    // Put heap right where __heap_start is (from linker script)
    if (!astro_get_symbol_addr(astro, HEAP_START_SYMBOL,
                               &astro->mem_ctx.heap_range.low_addr)) {
        astro_err = astro_errorf(astro, "where is my " HEAP_START_SYMBOL " symbol?");
        goto failure;
    }
    // zero-length heap for now
    astro->mem_ctx.heap_range.high_addr = astro->mem_ctx.heap_range.low_addr;

    // Start with a cute little 4K stack
    astro->mem_ctx.stack_range.low_addr = STACK_HIGH;
    astro->mem_ctx.stack_range.high_addr = STACK_HIGH;

    // now setup stack
    if (astro_err = astro_grow_stack(astro))
        goto failure;

    astro->mem_ctx.heap_blocks = NULL;

    // Setup malloc(), calloc(), realloc(), free() stubs
    #define SETUP_MALLOC_STUB(name) \
        if (astro_err = astro_stub_setup(astro, NULL, #name, name ## _stub)) \
            goto failure;

    SETUP_MALLOC_STUB(malloc);
    SETUP_MALLOC_STUB(free);
    SETUP_MALLOC_STUB(calloc);
    SETUP_MALLOC_STUB(realloc);

    return NULL;

    failure:
    return astro_err;
}

void astro_mem_ctx_cleanup(astro_t *astro) {
    if (!astro)
        return;

    // free linked list of heap blocks
    heap_block_t *b = astro->mem_ctx.heap_blocks;
    while (b) {
        heap_block_t *next = b->next;
        free(b);
        b = next;
    }

    // Don't keep stray pointers around
    astro->mem_ctx.heap_blocks = NULL;
}

const astro_err_t *astro_read_mem(astro_t *astro, uint64_t addr, size_t size,
                                  uint64_t *out) {
    uc_err err;
    const astro_err_t *astro_err;

    if (err = uc_mem_read(astro->uc, addr, out, size)) {
        astro_err = astro_uc_perror(astro, "astro_read_mem", err);
        goto failure;
    }

    return NULL;

    failure:
    return astro_err;
}

bool astro_is_freed_block(astro_t *astro, uint64_t addr) {
    heap_block_t *match = NULL;
    mem_ctx_heap_find_block(astro, addr, NULL, &match);
    return match && match->state == FREED;
}

bool astro_is_malloced_block(astro_t *astro, uint64_t addr) {
    heap_block_t *match = NULL;
    mem_ctx_heap_find_block(astro, addr, NULL, &match);
    return match && match->state == MALLOCED;
}

static bool in_addr_range(const addr_range_t *range, uint64_t addr) {
    return range->low_addr <= addr && addr < range->high_addr;
}

bool astro_is_stack_pointer(astro_t *astro, uint64_t addr) {
    return in_addr_range(&astro->mem_ctx.stack_range, addr);
}

bool astro_is_rw_static_pointer(astro_t *astro, uint64_t addr) {
    return in_addr_range(&astro->mem_ctx.bss_range, addr);
}

bool astro_is_ro_static_pointer(astro_t *astro, uint64_t addr) {
    return in_addr_range(&astro->mem_ctx.rodata_range, addr);
}

const astro_err_t *astro_malloced_block_size(astro_t *astro, uint64_t addr,
                                             size_t *out) {
    heap_block_t *match = NULL;
    mem_ctx_heap_find_block(astro, addr, NULL, &match);

    if (!match)
        return astro_errorf(astro, "block 0x%lx is not a malloced block", addr);

    if (out) *out = match->size;
    return NULL;
}
