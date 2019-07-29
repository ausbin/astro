// Memory management

#include <string.h>
#include "defs.h"

const char four_kb_of_zeros[0x1000];
char four_kb_of_uninit[0x1000];

static void mem_uninit_init(void) {
    memset(four_kb_of_uninit, UNINIT_BYTE, 0x1000);
}

static const astro_err_t *make_segfault_error(astro_t *astro, uc_mem_type type,
                                              uint64_t address, int size,
                                              const char *description) {
    const char *access_name;
    switch (type) {
        case UC_MEM_READ_UNMAPPED:
        case UC_MEM_READ_PROT:
            access_name = "read";
            break;

        case UC_MEM_WRITE_UNMAPPED:
        case UC_MEM_WRITE_PROT:
            access_name = "write";
            break;

        case UC_MEM_FETCH_UNMAPPED:
        case UC_MEM_FETCH_PROT:
            access_name = "jump";
            break;

        default:
            // Should not be reachable
            access_name = "access";
    }

    return astro_errorf(astro, "Segmentation Fault: invalid %s to "
                               "address 0x%lx (%s) of size %d bytes",
                               access_name, address, description, size);
}

static bool handle_segfault(uc_engine *uc, uc_mem_type type, uint64_t address,
                            int size, int64_t value, void *user_data) {
    (void)uc;
    (void)value;

    astro_t *astro = user_data;

    if (astro_is_access_within_stack_growth_region(astro, address, size)) {
        astro_grow_stack(astro);
        return true;
    } else {
        const char *description = address? "in the middle of nowhere" : "NULL";
        astro->exec_err = make_segfault_error(astro, type, address, size, description);
        return false;
    }
}

static bool validate_heap_access_hook(uc_engine *uc, uc_mem_type type,
                                      uint64_t address, int size,
                                      int64_t value, void *user_data) {
    (void)uc;
    (void)value;

    const char *description;
    astro_t *astro = user_data;

    // Iterate over heap blocks and check that this is inside the body
    // of a block. If not, treat this as a segfault, since it's better
    // to stop now since behavior is undefined if we continue on
    for (heap_block_t *b = astro->mem_ctx.heap_blocks; b; b = b->next) {
        if (b->addr <= address && address < b->addr + b->size + HEAP_BLOCK_PADDING*2) {
            switch (b->state) {
                case UNTOUCHED:
                description = "in a block not yet returned by malloc()";
                goto segfault;

                case FREED:
                description = "in a free()d block";
                goto segfault;

                case MALLOCED:
                if (address < b->addr + HEAP_BLOCK_PADDING) {
                    description = "in the padding before a heap block";
                    goto segfault;
                }
                if (address >= b->addr + HEAP_BLOCK_PADDING + b->size) {
                    description = "in the padding following a heap block";
                    goto segfault;
                }
                if (type == UC_MEM_READ && b->accessible < READABLE) {
                    description = "in a heap block marked unreadable by the tester";
                    goto segfault;
                }
                if (type == UC_MEM_WRITE && b->accessible < WRITABLE) {
                    description = "in a heap block marked unwritable by the tester";
                    goto segfault;
                }
                // all good
                return true;
            }
        }
    }

    // Shouldn't be possible: every address in the heap should be inside
    // a block (UNTOUCHED above should always cover this case)
    description = "unknown location in the heap";

    segfault:
    astro->exec_err = make_segfault_error(astro, type, address, size,
                                          description);
    return false;
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

    // If the heap was not empty, unregister the old heap hook
    if (astro->mem_ctx.heap_range.low_addr < astro->mem_ctx.heap_range.high_addr
            && (err = uc_hook_del(astro->uc, astro->mem_ctx.heap_hook))) {
        astro_err = astro_uc_perror(astro, "uc_hook_del old heap hook", err);
        goto failure;
    }

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

    // Register new heap hook
    uc_cb_eventmem_t heap_hook_cb = validate_heap_access_hook;
    if (err = uc_hook_add(astro->uc, &astro->mem_ctx.heap_hook,
                          UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                          FP2VOID(heap_hook_cb), astro,
                          astro->mem_ctx.heap_range.low_addr,
                          astro->mem_ctx.heap_range.high_addr-1)) {
        astro_err = astro_uc_perror(astro, "uc_hook_add new heap hook", err);
        goto failure;
    }

    *block_out = new_block;
    return NULL;

    failure:
    free(new_block);
    return astro_err;
}

static const astro_err_t *mem_ctx_heap_malloc(astro_t *astro, uint64_t size,
                                              accessible_t accessible,
                                              freeable_t freeable,
                                              uint64_t *addr_out) {
    if (astro->mem_ctx.mallocs_until_fail >= 0) {
        if (!astro->mem_ctx.mallocs_until_fail) {
            *addr_out = 0;
            return NULL;
        } else {
            astro->mem_ctx.mallocs_until_fail--;
        }
    }

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
    result->accessible = accessible;
    result->freeable = freeable;
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
    } else if (match->freeable == NOT_FREEABLE) {
        astro_err = astro_errorf(astro, "free()ing a pointer 0x%lx that "
                                        "you're not allowed to free. This is "
                                        "probably a pointer passed to your "
                                        "code by the tester you have no need "
                                        "to free.", addr);
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
    if (astro_err = mem_ctx_heap_malloc(astro, total_size, WRITABLE, FREEABLE,
                                        &addr))
        goto failure;

    if (addr) {
        // Zero out the block 4K at a time
        for (uint64_t a = addr; a < addr + total_size; a += 0x1000) {
            uint64_t n = MIN(addr + total_size - a, 0x1000);

            if (err = uc_mem_write(astro->uc, a, four_kb_of_zeros, n)) {
                astro_err = astro_uc_perror(astro, "uc_mem_write calloc", err);
                goto failure;
            }
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
        if (!mem_ctx_heap_malloc(astro, size, WRITABLE, FREEABLE, &addr))
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
    if (astro_err = mem_ctx_heap_malloc(astro, size, WRITABLE, FREEABLE,
                                        &addr))
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
    astro->mem_ctx.mallocs_until_fail = -1;

    // Register segfault handler
    uc_err err;
    uc_hook hh;
    uc_cb_eventmem_t segfault_cb = handle_segfault;
    if (err = uc_hook_add(astro->uc, &hh, UC_HOOK_MEM_INVALID,
                          FP2VOID(segfault_cb), astro, MIN_ADDR, MAX_ADDR)) {
        astro_err = astro_uc_perror(astro, "uc_hook_add segfault handler", err);
        goto failure;
    }

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
                                  void *out) {
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

const astro_err_t *astro_write_mem(astro_t *astro, uint64_t addr, size_t size,
                                   const void *data) {
    uc_err err;
    const astro_err_t *astro_err;

    if (err = uc_mem_write(astro->uc, addr, data, size)) {
        astro_err = astro_uc_perror(astro, "astro_write_mem", err);
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

void astro_heap_iterate(astro_t *astro, astro_heap_iterator_t *iter_mem) {
    if (!astro || !iter_mem)
        return;

    iter_mem->next = astro->mem_ctx.heap_blocks;
}

const astro_heap_block_t *astro_heap_iterate_next(astro_heap_iterator_t *iter) {
    // User should only see currently malloced blocks
    while (iter->next && iter->next->state != MALLOCED)
        iter->next = iter->next->next;

    if (!iter->next)
        return NULL;

    iter->block_mem.addr = iter->next->addr + HEAP_BLOCK_PADDING;
    iter->block_mem.size = iter->next->size;
    iter->next = iter->next->next;

    return &iter->block_mem;
}

void astro_set_mallocs_until_fail(astro_t *astro, int mallocs_until_fail) {
    if (!astro)
        return;

    astro->mem_ctx.mallocs_until_fail = mallocs_until_fail;
}

const astro_err_t *astro_malloc(astro_t *astro, uint64_t size,
                                accessible_t accessible, freeable_t freeable,
                                uint64_t *addr_out) {
    return mem_ctx_heap_malloc(astro, size, accessible, freeable, addr_out);
}
