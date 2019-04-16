#include "defs.h"

// Contains code for calling/stubbing functions

#define MAX_STUBS 64
static struct stub {
    int valid;
    astro_t *astro;
    void *user_data;
    stub_impl_t impl;
    uc_hook hook;
} stubs[MAX_STUBS];

// Register used for return value
#define ARG_REG_RET UC_X86_REG_RAX

static const int ARG_REGS[] = {
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_RCX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
};

int call_function(astro_t *astro, uint64_t *ret, size_t n,
                  const char *name, ...) {
    uc_err err;

    if (n > sizeof ARG_REGS / sizeof *ARG_REGS) {
        fprintf(stderr, "unsupported number of args %lu\n", n);
        goto failure;
    }

    uint64_t func_addr;
    if (!get_symbol_addr(astro, name, &func_addr)) {
        fprintf(stderr, "cannot find symbol `%s'\n", name);
        goto failure;
    }

    // at the entry point, there's a halt instruction which
    // stops the simulation
    uint64_t return_address;
    if (!get_entry_point_addr(astro, &return_address))
        goto failure;

    uint64_t stack_bottom = astro->mem_ctx.stack_end - 8;

    if (err = uc_mem_write(astro->uc, stack_bottom, &return_address, 8)) {
        fprintf(stderr, "uc_mem_write return address: %s\n", uc_strerror(err));
        goto failure;
    }

    // set stack pointer
    if (err = uc_reg_write(astro->uc, UC_X86_REG_RSP, &stack_bottom)) {
        fprintf(stderr, "uc_reg_write %%rsp: %s\n", uc_strerror(err));
        goto failure;
    }

    // go ahead and clear base pointer for fun
    uint64_t zero = 0;
    if (err = uc_reg_write(astro->uc, UC_X86_REG_RBP, &zero)) {
        fprintf(stderr, "uc_reg_write %%rbp: %s\n", uc_strerror(err));
        goto failure;
    }

    va_list ap;
    va_start(ap, name);

    for (size_t i = 0; i < n; i++) {
        uint64_t arg = va_arg(ap, uint64_t);

        if (err = uc_reg_write(astro->uc, ARG_REGS[i], &arg)) {
            fprintf(stderr, "uc_reg_write arg #%lu: %s\n", i+1, uc_strerror(err));
            va_end(ap);
            goto failure;
        }
    }

    va_end(ap);

    if (err = uc_emu_start(astro->uc, func_addr, 0, 0, 0)) {
        // Let the segfault handler take care of segfaults
        if (err != UC_ERR_READ_UNMAPPED &&
            err != UC_ERR_WRITE_UNMAPPED &&
            err != UC_ERR_FETCH_UNMAPPED &&
            err != UC_ERR_WRITE_PROT &&
            err != UC_ERR_READ_PROT &&
            err != UC_ERR_FETCH_PROT)
            fprintf(stderr, "uc_emu_start %s(): %s\n", name, uc_strerror(err));
        goto failure;
    }

    if (ret) {
        if (err = uc_reg_read(astro->uc, UC_X86_REG_RAX, ret)) {
            fprintf(stderr, "uc_reg_read %%rax: %s\n", uc_strerror(err));
            goto failure;
        }
    }

    return 1;

    failure:
    return 0;
}

enum stack_state {
    STACK_STATE_STUB,
    STACK_STATE_ERROR
};

static int _print_backtrace(astro_t *astro, enum stack_state stack_state) {
    uc_err err;

    // call_function() above pushes the ELF entry point onto the stack
    // before starting the simulator, since there's only a hlt at that
    // address (halting the simulator). We don't need to include that in
    // the backtrace (should be "magic" to students). So grab the entry
    // point from the ELF header, and stop printing when we hit it
    uint64_t final_return_addr;
    if (!get_entry_point_addr(astro, &final_return_addr))
        goto failure;

    uint64_t base_pointer;

    if (err = uc_reg_read(astro->uc, UC_X86_REG_RBP, &base_pointer)) {
        fprintf(stderr, "uc_reg_read %%rbp for backtrace: %s\n", uc_strerror(err));
        goto failure;
    }

    uint64_t return_addr;

    if (stack_state == STACK_STATE_STUB) {
        // If backtrace is being called from a stub, the top of the
        // stack is the return address pushed by student code. So grab
        // it off so we can use it to print the line that called
        // the stub
        uint64_t stack_top_ptr;

        if (err = uc_reg_read(astro->uc, UC_X86_REG_RSP, &stack_top_ptr)) {
            fprintf(stderr, "uc_reg_read %%rsp for backtrace: %s\n", uc_strerror(err));
            goto failure;
        }

        // Read return address off stack (currently the top of the stack,
        // since stubs don't touch it)
        if (err = uc_mem_read(astro->uc, stack_top_ptr, &return_addr, 8)) {
            fprintf(stderr, "uc_mem_read address 0x%lx (%%rbp + 8) for "
                    "backtrace: %s\n", stack_top_ptr, uc_strerror(err));
            goto failure;
        }
    } else {
        // If backtrace is being called in response to a student
        // whoopsie daisy, then we want to start the backtrace at %rip,
        // the PC
        if (err = uc_reg_read(astro->uc, UC_X86_REG_RIP, &return_addr)) {
            fprintf(stderr, "uc_reg_read %%rip for backtrace: %s\n", uc_strerror(err));
            goto failure;
        }

        // HACK: Account for the -1 in the loop below
        return_addr++;
    }

    fprintf(stderr, "backtrace:\n");

    // TODO: give up after n iterations (for infinite loops)
    // call_function() above sets %rbp = 0 and pushes the ELF entry
    // point onto the stack when calling a function
    while (return_addr != final_return_addr && base_pointer) {
        // Back up into the last instruction: we want the instruction
        // that made the function call, not the return address
        // TODO: does this always work?
        uint64_t prev_instr_addr = return_addr - 1;

        // Find the Compilation Unit Debugging Information Entry (CU
        // DIE) corresponding to this address
        Dwarf_Die cu_die;
        if (!dwarf_addrdie(astro->dwarf, prev_instr_addr, &cu_die)) {
            fprintf(stderr, "dwarf_addrdie for address 0x%lx for "
                    "backtrace: %s\n", prev_instr_addr, dwarf_errmsg(-1));
            goto failure;
        }

        Dwarf_Die *scopes = NULL;
        int nscopes = dwarf_getscopes(&cu_die, prev_instr_addr, &scopes);
        if (nscopes <= 0) {
            fprintf(stderr, "dwarf_getscopes for address 0x%lx: %s\n",
                    prev_instr_addr,
                    (nscopes == 0)? "no scopes found!" : dwarf_errmsg(-1));
            free(scopes);
            goto failure;
        }

        // Search scopes for function to which this belongs
        const char *function_name = NULL;
        for (int i = 0; !function_name && i < nscopes; i++) {
            if (dwarf_tag(&scopes[i]) == DW_TAG_subprogram) {
                function_name = dwarf_diename(&scopes[i]);

                if (!function_name) {
                    fprintf(stderr, "dwarf_diename: %s\n", dwarf_errmsg(-1));
                    free(scopes);
                    goto failure;
                }
            }
        }

        free(scopes);

        if (!function_name) {
            fprintf(stderr, "can't find function name for 0x%lx\n", prev_instr_addr);
            goto failure;
        }

        // Find the line for this address
        Dwarf_Line *line;
        if (!(line = dwarf_getsrc_die(&cu_die, prev_instr_addr))) {
            fprintf(stderr, "dwarf_getsrc_die for address 0x%lx for "
                    "backtrace: %s\n", return_addr, dwarf_errmsg(-1));
            goto failure;
        }

        const char *filename;
        if (!(filename = dwarf_linesrc(line, NULL, NULL))) {
            fprintf(stderr, "dwarf_linesrc for address 0x%lx for "
                    "backtrace: %s\n", return_addr, dwarf_errmsg(-1));
            goto failure;
        }

        int lineno;
        dwarf_lineno(line, &lineno);

        fprintf(stderr, "  %s() at %s:%d\n", function_name, filename, lineno);

        // Now: go to the next stack frame.
        // Saved %eip was pushed onto stack right before saved %ebp was
        uint64_t return_addr_ptr = base_pointer + 8;

        // Read return address off stack (pushed right before saved %rbp)
        if (err = uc_mem_read(astro->uc, return_addr_ptr, &return_addr, 8)) {
            fprintf(stderr, "uc_mem_read address 0x%lx (%%rbp + 8) for "
                    "backtrace: %s\n", return_addr_ptr, uc_strerror(err));
            goto failure;
        }

        if (err = uc_mem_read(astro->uc, base_pointer, &base_pointer, 8)) {
            fprintf(stderr, "uc_mem_read address 0x%lx (%%rbp) for "
                    "backtrace: %s\n", base_pointer, uc_strerror(err));
            goto failure;
        }
    }

    return 1;

    failure:
    return 0;
}

// Use this when you want to print a backtrace in a stub
int stub_print_backtrace(astro_t *astro) {
    return _print_backtrace(astro, STACK_STATE_STUB);
}

// Use this when their code is executing and they screw up
int print_backtrace(astro_t *astro) {
    return _print_backtrace(astro, STACK_STATE_ERROR);
}

static void stub_hook_callback(uc_engine *uc, uint64_t addr, uint32_t size,
                               void *user_data) {
    (void)uc;
    (void)addr;
    (void)size;

    struct stub *stub = user_data;
    stub->impl(stub->astro, stub->user_data);
}

int stub_arg(astro_t *astro, size_t idx, uint64_t *arg_out) {
    if (idx >= sizeof ARG_REGS / sizeof *ARG_REGS) {
        fprintf(stderr, "unsupported args index %lu\n", idx);
        goto failure;
    }

    uc_err err;
    if (err = uc_reg_read(astro->uc, ARG_REGS[idx], arg_out)) {
        fprintf(stderr, "uc_reg_read arg index %lu: %s\n", idx,
                uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}

int stub_ret(astro_t *astro, uint64_t retval) {
    uc_err err;
    if (err = uc_reg_write(astro->uc, ARG_REG_RET, &retval)) {
        fprintf(stderr, "uc_reg_write return value: %s\n",
                uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}

void stub_die(astro_t *astro) {
    uc_err err;
    // No way to handle this error, but print it anyway
    if (err = uc_emu_stop(astro->uc))
        fprintf(stderr, "uc_emu_stop: %s\n", uc_strerror(err));
}

int stub_setup(astro_t *astro, void *user_data, const char *name,
               stub_impl_t impl) {
    uint64_t func_addr;
    if (!get_symbol_addr(astro, name, &func_addr)) {
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
    stub->astro = astro;
    stub->user_data = user_data;
    stub->impl = impl;

    uc_err err;
    uc_cb_hookcode_t hook_cb = stub_hook_callback;

    if (err = uc_hook_add(astro->uc, &stub->hook, UC_HOOK_CODE,
                          FP2VOID(hook_cb), stub, func_addr, func_addr)) {
        fprintf(stderr, "uc_hook_add for stub %s: %s\n", name, uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}
