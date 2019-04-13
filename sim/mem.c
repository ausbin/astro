// Memory management

#include <string.h>
#include "defs.h"

const char four_kb_of_zeros[0x1000];
char four_kb_of_uninit[0x1000];

extern void mem_uninit_init(void) {
    memset(four_kb_of_uninit, UNINIT_BYTE, 0x1000);
}

static int grow_stack(mem_ctx_t *ctx, uc_engine *uc, bool unregister);

static bool mem_ctx_grow_stack_hook(uc_engine *uc, uc_mem_type type,
                                    uint64_t address, int size, int64_t value,
                                    void *user_data) {
    // Don't need these guys since this hook is only called when we need
    // to grow the stack 4K into lower memory
    (void)type;
    (void)address;
    (void)size;
    (void)value;

    mem_ctx_t *ctx = user_data;
    if (!grow_stack(ctx, uc, false))
        return false;

    return true;
}

static int grow_stack(mem_ctx_t *ctx, uc_engine *uc, bool unregister) {
    uc_err err;

    ctx->stack_start -= 0x1000;

    if (err = uc_mem_map(uc, ctx->stack_start, 0x1000, UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map stack: %s\n", uc_strerror(err));
        goto failure;
    }
    if (err = uc_mem_write(uc, ctx->stack_start, four_kb_of_uninit, 0x1000)) {
        fprintf(stderr, "uc_mem_write stack: %s\n", uc_strerror(err));
        goto failure;
    }

    if (unregister && (err = uc_hook_del(uc, ctx->stack_hook))) {
        fprintf(stderr, "uc_hook_del stack hook: %s\n", uc_strerror(err));
        goto failure;
    }

    uc_cb_eventmem_t hook_cb = mem_ctx_grow_stack_hook;

    if (err = uc_hook_add(uc, &ctx->stack_hook,
                          UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                          FP2VOID(hook_cb), ctx,
                          ctx->stack_start - 0x1000, ctx->stack_start - 1)) {
        fprintf(stderr, "uc_hook_add: %s\n", uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}

// sbrk(), basically
static int mem_ctx_grow_heap(uc_engine *uc, mem_ctx_t *ctx,
                             uint64_t size, heap_block_t **block_out) {
    uc_err err;
    heap_block_t *new_block = NULL;
    uint64_t size_rounded = ROUND_TO_4K(size + 2*HEAP_BLOCK_PADDING);

    if (err = uc_mem_map(uc, ctx->heap_end, size_rounded, UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map heap space: %s\n", uc_strerror(err));
        goto failure;
    }

    // Initialize memory
    for (uint64_t a = ctx->heap_end; a < ctx->heap_end + size_rounded; a += 0x1000) {
        if (err = uc_mem_write(uc, a, four_kb_of_uninit, 0x1000)) {
            fprintf(stderr, "uc_mem_write initialize heap space: %s\n", uc_strerror(err));
            goto failure;
        }
    }

    new_block = malloc(sizeof (heap_block_t));
    if (!new_block) {
        perror("malloc");
        goto failure;
    }

    new_block->addr = ctx->heap_end;
    new_block->size = size_rounded - 2*HEAP_BLOCK_PADDING;
    new_block->alloced = 0;
    new_block->next = NULL;

    heap_block_t *tail = ctx->heap_blocks;
    while (tail && tail->next)
        tail = tail->next;
    if (!tail)
        ctx->heap_blocks = new_block;
    else
        tail->next = new_block;

    ctx->heap_end += size_rounded;

    *block_out = new_block;
    return 1;

    failure:
    free(new_block);
    return 0;
}

static int mem_ctx_heap_malloc(uc_engine *uc, mem_ctx_t *ctx,
                               uint64_t size, uint64_t *addr_out) {
    heap_block_t *exact_match = NULL;
    heap_block_t *split_match = NULL;

    for (heap_block_t *b = ctx->heap_blocks;
         b && !exact_match && !split_match;
         b = b->next)
        if (!b->alloced && b->size == size)
            exact_match = b;
        else if (!b->alloced && b->size >= size + 2*HEAP_BLOCK_PADDING + 1)
            split_match = b;

    // Need to map some more space
    if (!exact_match && !split_match) {
        heap_block_t *new_block;
        if (!mem_ctx_grow_heap(uc, ctx, size, &new_block))
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

// merge right block into left
static void mem_ctx_heap_merge(heap_block_t *left, heap_block_t *right) {
    if (left && right && !left->alloced && !right->alloced &&
            left->addr + 2*HEAP_BLOCK_PADDING + left->size == right->addr) {
        left->size += 2*HEAP_BLOCK_PADDING + right->size;
        left->next = right->next;
        free(right);
    }
}

static int mem_ctx_heap_free(mem_ctx_t *ctx, uint64_t addr) {
    heap_block_t *prev = NULL;
    heap_block_t *match = NULL;

    for (heap_block_t *b = ctx->heap_blocks; !match && b; b = b->next) {
        if (b->addr + HEAP_BLOCK_PADDING == addr) {
            if (b->alloced) {
                match = b;
            } else {
                // TODO: this error message is garbage
                // TODO: not necessarily a double free
                fprintf(stderr, "Double free() of address 0x%lx!\n", addr);
                goto failure;
            }
        }

        if (!match)
            prev = b;
    }

    if (!match) {
        // TODO: this error message is garbage
        fprintf(stderr, "free()ing garbage pointer 0x%lx!\n", addr);
        goto failure;
    }

    match->alloced = 0;
    mem_ctx_heap_merge(match, match->next);
    mem_ctx_heap_merge(prev, match);

    return 1;

    failure:
    return 0;
}

static void malloc_stub(uc_engine *uc, Elf *elf, void *user_data) {
    (void)uc;
    (void)elf;

    mem_ctx_t *ctx = user_data;

    uint64_t size;
    if (!stub_arg(uc, 0, &size))
        goto failure;

    uint64_t addr = 0;
    if (!mem_ctx_heap_malloc(uc, ctx, size, &addr))
        goto failure;

    if (!stub_ret(uc, addr))
        goto failure;

    return;

    failure:
    stub_die(uc);
}

static void free_stub(uc_engine *uc, Elf *elf, void *user_data) {
    (void)uc;
    (void)elf;

    mem_ctx_t *ctx = user_data;

    uint64_t addr;
    if (!stub_arg(uc, 0, &addr))
        goto failure;

    if (!mem_ctx_heap_free(ctx, addr))
        goto failure;

    return;

    failure:
    stub_die(uc);
}

mem_ctx_t *mem_ctx_new(uc_engine *uc, Elf *elf) {
    mem_ctx_t *ctx = malloc(sizeof (mem_ctx_t));
    if (!ctx)
        goto failure;

    // Now, need to setup stack and heap -- allocate 8K for each
    // Put heap right where __heap_start is (from linker script)
    if (!get_symbol_addr(elf, "__heap_start", &ctx->heap_start)) {
        fprintf(stderr, "where is my __heap_start symbol?\n");
        goto failure;
    }
    // zero-length heap for now
    ctx->heap_end = ctx->heap_start;

    // Start with a cute little 4K stack
    ctx->stack_end = STACK_HIGH;
    ctx->stack_start = STACK_HIGH;

    // now setup stack
    if (!grow_stack(ctx, uc, false))
        goto failure;

    ctx->heap_blocks = NULL;

    // Setup malloc(), free() stubs
    if (!stub_setup(uc, elf, ctx, "malloc", malloc_stub))
        goto failure;
    if (!stub_setup(uc, elf, ctx, "free", free_stub))
        goto failure;

    return ctx;

    failure:
    free(ctx);
    return NULL;
}

void mem_ctx_free(mem_ctx_t *ctx) {
    if (!ctx)
        return;

    // free linked list of heap blocks
    heap_block_t *b = ctx->heap_blocks;
    while (b) {
        heap_block_t *next = b->next;
        free(b);
        b = next;
    }

    free(ctx);
}
