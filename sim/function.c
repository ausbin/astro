#include "defs.h"

// Contains code for calling/stubbing functions

#define MAX_STUBS 64
static struct stub {
    int valid;
    Elf *elf;
    void *user_data;
    stub_impl_t impl;
    uc_hook hook;
} stubs[MAX_STUBS];

static const int ARG_REGS[] = {
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_RCX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
};

int call_function(uc_engine *uc, Elf *elf, uint64_t stack_bottom,
                  uint64_t *ret, size_t n, const char *name, ...) {
    uc_err err;

    if (n > sizeof ARG_REGS / sizeof *ARG_REGS) {
        fprintf(stderr, "unsupported number of args %lu\n", n);
        goto failure;
    }

    uint64_t func_addr;
    if (!get_symbol_addr(elf, name, &func_addr)) {
        fprintf(stderr, "cannot find symbol `%s'\n", name);
        goto failure;
    }

    // at the entry point, there's a halt instruction which
    // stops the simulation
    uint64_t return_address;
    if (!get_entry_point_addr(elf, &return_address))
        goto failure;

    stack_bottom -= 8;

    if (err = uc_mem_write(uc, stack_bottom, &return_address, 8)) {
        fprintf(stderr, "uc_mem_write return address: %s\n", uc_strerror(err));
        goto failure;
    }

    // set stack pointer
    if (err = uc_reg_write(uc, UC_X86_REG_RSP, &stack_bottom)) {
        fprintf(stderr, "uc_reg_write %%rsp: %s\n", uc_strerror(err));
        goto failure;
    }

    // go ahead and clear base pointer for fun
    uint64_t zero = 0;
    if (err = uc_reg_write(uc, UC_X86_REG_RBP, &zero)) {
        fprintf(stderr, "uc_reg_write %%rbp: %s\n", uc_strerror(err));
        goto failure;
    }

    va_list ap;
    va_start(ap, name);

    for (size_t i = 0; i < n; i++) {
        uint64_t arg = va_arg(ap, uint64_t);

        if (err = uc_reg_write(uc, ARG_REGS[i], &arg)) {
            fprintf(stderr, "uc_reg_write arg #%lu: %s\n", i+1, uc_strerror(err));
            va_end(ap);
            goto failure;
        }
    }

    va_end(ap);

    if (err = uc_emu_start(uc, func_addr, 0, 0, 0)) {
        fprintf(stderr, "uc_emu_start %s(): %s\n", name, uc_strerror(err));
        goto failure;
    }

    if (ret) {
        if (err = uc_reg_read(uc, UC_X86_REG_RAX, ret)) {
            fprintf(stderr, "uc_reg_read %%rax: %s\n", uc_strerror(err));
            goto failure;
        }
    }

    return 1;

    failure:
    return 0;
}

static void stub_hook_callback(uc_engine *uc, uint64_t addr, uint32_t size,
                               void *user_data) {
    (void)addr;
    (void)size;

    struct stub *stub = user_data;
    stub->impl(uc, stub->elf, stub->user_data);
}

int stub_arg(uc_engine *uc, size_t idx, uint64_t *arg_out) {
    if (idx >= sizeof ARG_REGS / sizeof *ARG_REGS) {
        fprintf(stderr, "unsupported args index %lu\n", idx);
        goto failure;
    }

    uc_err err;
    if (err = uc_reg_read(uc, ARG_REGS[idx], arg_out)) {
        fprintf(stderr, "uc_reg_read arg index %lu: %s\n", idx,
                uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}

int stub_setup(uc_engine *uc, Elf *elf, void *user_data, const char *name,
               stub_impl_t impl) {
    uint64_t func_addr;
    if (!get_symbol_addr(elf, name, &func_addr)) {
        fprintf(stderr, "cannot find symbol `%s'\n", name);
        goto failure;
    }

    int i = 0;
    for (; i < MAX_STUBS && stubs[i].valid; i++);

    if (i == MAX_STUBS) {
        fprintf(stderr, "max number of stubs %d reached, can't create stub\n",
                MAX_STUBS);
        goto failure;
    }

    struct stub *stub = &stubs[i];
    stub->valid = 1;
    stub->elf = elf;
    stub->user_data = user_data;
    stub->impl = impl;

    uc_err err;
    uc_cb_hookcode_t hook_cb = stub_hook_callback;

    if (err = uc_hook_add(uc, &stub->hook, UC_HOOK_CODE, FP2VOID(hook_cb), stub,
                          func_addr, func_addr)) {
        fprintf(stderr, "uc_hook_add for stub %s: %s\n", name, uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}
