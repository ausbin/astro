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

    astro->mem_ctx.stack_start -= 0x1000;

    if (err = uc_mem_map(astro->uc, astro->mem_ctx.stack_start, 0x1000,
                         UC_PROT_READ | UC_PROT_WRITE)) {
        astro_err = astro_uc_perror(astro, "uc_mem_map stack", err);
        goto failure;
    }
    if (err = uc_mem_write(astro->uc, astro->mem_ctx.stack_start,
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
    return addr >= astro->mem_ctx.stack_start - 0x1000 &&
           addr <= astro->mem_ctx.stack_start - 1 &&
           end_addr >= astro->mem_ctx.stack_start - 0x1000 &&
           end_addr <= astro->mem_ctx.stack_start - 1;
}

// sbrk(), basically
static int mem_ctx_grow_heap(astro_t *astro, uint64_t size,
                                   heap_block_t **block_out) {
    uc_err err;
    heap_block_t *new_block = NULL;
    uint64_t size_rounded = ROUND_TO_4K(size + 2*HEAP_BLOCK_PADDING);

    if (err = uc_mem_map(astro->uc, astro->mem_ctx.heap_end, size_rounded,
                         UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map heap space: %s\n", uc_strerror(err));
        goto failure;
    }

    // Initialize memory
    for (uint64_t a = astro->mem_ctx.heap_end;
         a < astro->mem_ctx.heap_end + size_rounded;
         a += 0x1000) {
        if (err = uc_mem_write(astro->uc, a, four_kb_of_uninit, 0x1000)) {
            fprintf(stderr, "uc_mem_write initialize heap space: %s\n",
                    uc_strerror(err));
            goto failure;
        }
    }

    new_block = malloc(sizeof (heap_block_t));
    if (!new_block) {
        perror("malloc");
        goto failure;
    }

    new_block->addr = astro->mem_ctx.heap_end;
    new_block->size = size_rounded - 2*HEAP_BLOCK_PADDING;
    new_block->alloced = 0;
    new_block->next = NULL;

    heap_block_t *tail = astro->mem_ctx.heap_blocks;
    while (tail && tail->next)
        tail = tail->next;
    if (!tail)
        astro->mem_ctx.heap_blocks = new_block;
    else
        tail->next = new_block;

    astro->mem_ctx.heap_end += size_rounded;

    *block_out = new_block;
    return 1;

    failure:
    free(new_block);
    return 0;
}

static int mem_ctx_heap_malloc(astro_t *astro, uint64_t size,
                                     uint64_t *addr_out) {
    heap_block_t *exact_match = NULL;
    heap_block_t *split_match = NULL;

    for (heap_block_t *b = astro->mem_ctx.heap_blocks;
         b && !exact_match && !split_match;
         b = b->next)
        if (!b->alloced && b->size == size)
            exact_match = b;
        else if (!b->alloced && b->size >= size + 2*HEAP_BLOCK_PADDING + 1)
            split_match = b;

    // Need to map some more space
    if (!exact_match && !split_match) {
        heap_block_t *new_block;
        if (!mem_ctx_grow_heap(astro, size, &new_block))
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
            perror("malloc");
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

    result->alloced = 1;
    *addr_out = result->addr + HEAP_BLOCK_PADDING;

    return 1;

    failure:
    *addr_out = 0;
    return 0;
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

// merge right block into left
static void mem_ctx_heap_merge(heap_block_t *left, heap_block_t *right) {
    if (left && right && !left->alloced && !right->alloced &&
            left->addr + 2*HEAP_BLOCK_PADDING + left->size == right->addr) {
        left->size += 2*HEAP_BLOCK_PADDING + right->size;
        left->next = right->next;
        free(right);
    }
}

static int mem_ctx_heap_free(astro_t *astro, uint64_t addr) {
    heap_block_t *prev = NULL;
    heap_block_t *match = NULL;

    mem_ctx_heap_find_block(astro, addr, &prev, &match);

    if (!match) {
        // TODO: this error message is garbage
        fprintf(stderr, "free()ing garbage pointer 0x%lx!\n", addr);
        goto failure;
    }

    if (!match->alloced) {
        // TODO: this error message is garbage
        // TODO: not necessarily a double free
        fprintf(stderr, "Double free() of address 0x%lx!\n", addr);
        goto failure;
    }

    match->alloced = 0;
    mem_ctx_heap_merge(match, match->next);
    mem_ctx_heap_merge(prev, match);

    return 1;

    failure:
    return 0;
}

// TODO: Will these error messages say malloc()? Is that too confusing?
static int mem_ctx_heap_calloc(astro_t *astro, uint64_t nmemb, uint64_t size,
                               uint64_t *addr_out) {
    uc_err err;
    uint64_t total_size = nmemb * size;

    uint64_t addr = 0;
    if (!mem_ctx_heap_malloc(astro, total_size, &addr))
        goto failure;

    // Zero out the block 4K at a time
    for (uint64_t a = addr; a < addr + total_size; a += 0x1000) {
        uint64_t n = MIN(addr + total_size - a, 0x1000);

        if (err = uc_mem_write(astro->uc, a, four_kb_of_zeros, n)) {
            fprintf(stderr, "uc_mem_write calloc: %s\n", uc_strerror(err));
            goto failure;
        }
    }

    *addr_out = addr;
    return 1;

    failure:
    *addr_out = 0;
    return 0;
}

// TODO: Will these error messages say malloc()/free()? Is that too confusing?
static int mem_ctx_heap_realloc(astro_t *astro, uint64_t ptr, uint64_t size,
                                uint64_t *addr_out) {
    uc_err err;
    heap_block_t *match = NULL;
    uint64_t existing_size = 0;

    if (ptr) {
        mem_ctx_heap_find_block(astro, ptr, NULL, &match);

        if (!match) {
            // TODO: this error message is garbage
            fprintf(stderr, "realloc()ing garbage pointer 0x%lx!\n", ptr);
            goto failure;
        }

        if (!match->alloced) {
            // TODO: this error message is semi garbage
            fprintf(stderr, "realloc() called on free block 0x%lx! Do not "
                            "free() a pointer before passing it to ralloc()!\n",
                    ptr);
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
            perror("malloc");
            goto failure;
        }

        // Copy 4K at a time
        for (uint64_t a = ptr; a < ptr + copy_size; a += 0x1000) {
            uint64_t n = MIN(ptr + copy_size - a, 0x1000);

            if (err = uc_mem_read(astro->uc, a, tmp_buf, n)) {
                fprintf(stderr, "uc_mem_read realloc: %s\n", uc_strerror(err));
                goto failure;
            }

            if (err = uc_mem_write(astro->uc, a, tmp_buf, n)) {
                fprintf(stderr, "uc_mem_write realloc: %s\n", uc_strerror(err));
                goto failure;
            }
        }
    }

    // If they passed an old block, free it now
    if (ptr && !mem_ctx_heap_free(astro, ptr))
        goto failure;

    *addr_out = addr;
    return 1;

    failure:
    *addr_out = 0;
    return 0;
}

static void malloc_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    uint64_t size;
    if (!astro_stub_arg(astro, 0, &size))
        goto failure;

    uint64_t addr = 0;
    if (!mem_ctx_heap_malloc(astro, size, &addr))
        goto failure;

    if (!astro_stub_ret(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro);
}

static void free_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    uint64_t addr;
    if (!astro_stub_arg(astro, 0, &addr))
        goto failure;

    if (!mem_ctx_heap_free(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro);
}

static void calloc_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    uint64_t nmemb;
    if (!astro_stub_arg(astro, 0, &nmemb))
        goto failure;
    uint64_t size;
    if (!astro_stub_arg(astro, 1, &size))
        goto failure;

    uint64_t addr = 0;
    if (!mem_ctx_heap_calloc(astro, nmemb, size, &addr))
        goto failure;

    if (!astro_stub_ret(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro);
}

static void realloc_stub(astro_t *astro, void *user_data) {
    (void)user_data;

    uint64_t ptr;
    if (!astro_stub_arg(astro, 0, &ptr))
        goto failure;
    uint64_t size;
    if (!astro_stub_arg(astro, 1, &size))
        goto failure;

    uint64_t addr = 0;
    if (!mem_ctx_heap_realloc(astro, ptr, size, &addr))
        goto failure;

    if (!astro_stub_ret(astro, addr))
        goto failure;

    return;

    failure:
    astro_stub_die(astro);
}

const astro_err_t *astro_mem_ctx_setup(astro_t *astro) {
    const astro_err_t *astro_err = NULL;

    // Set 4K of uninitialized memory to 0x69s
    // (reused to initialize memory deterministically)
    mem_uninit_init();

    // Now, need to setup stack and heap -- allocate 8K for each
    // Put heap right where __heap_start is (from linker script)
    if (!astro_get_symbol_addr(astro, HEAP_START_SYMBOL,
                               &astro->mem_ctx.heap_start)) {
        astro_err = astro_errorf(astro, "where is my " HEAP_START_SYMBOL " symbol?");
        goto failure;
    }
    // zero-length heap for now
    astro->mem_ctx.heap_end = astro->mem_ctx.heap_start;

    // Start with a cute little 4K stack
    astro->mem_ctx.stack_end = STACK_HIGH;
    astro->mem_ctx.stack_start = STACK_HIGH;

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
