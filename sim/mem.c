// Memory management

#include "defs.h"

static int grow_stack(mem_ctx *ctx, uc_engine *uc, bool unregister);

static bool mem_ctx_grow_stack_hook(uc_engine *uc, uc_mem_type type,
                                    uint64_t address, int size, int64_t value,
                                    void *user_data) {
    // Don't need these guys since this hook is only called when we need
    // to grow the stack 4K into lower memory
    (void)type;
    (void)address;
    (void)size;
    (void)value;

    mem_ctx *ctx = user_data;
    if (!grow_stack(ctx, uc, false))
        return false;

    return true;
}

static int grow_stack(mem_ctx *ctx, uc_engine *uc, bool unregister) {
    uc_err err;

    ctx->stack_start -= 0x1000;

    if (err = uc_mem_map(uc, ctx->stack_start, 0x1000, UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map stack: %s\n", uc_strerror(err));
        goto failure;
    }
    if (err = uc_mem_write(uc, ctx->stack_start, four_kb_of_zeros, 0x1000)) {
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

mem_ctx *mem_ctx_new(uc_engine *uc, Elf *elf) {
    mem_ctx *ctx = malloc(sizeof (mem_ctx));
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

    return ctx;

    failure:
    free(ctx);
    return NULL;
}
