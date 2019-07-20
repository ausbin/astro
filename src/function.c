#include <string.h>
#include "defs.h"

// Contains code for calling/stubbing functions

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

const astro_err_t *astro_mock_func(astro_t *astro, const char *func_name,
                                   const char *mock_func_name) {
    size_t mock_funcs_len = sizeof astro->mock_funcs / sizeof astro->mock_funcs[0];
    for (unsigned int i = 0; i < mock_funcs_len; i++) {
        if (!astro->mock_funcs[i].func_name &&
                !astro->mock_funcs[i].mock_func_name) {
            astro->mock_funcs[i].func_name = func_name;
            astro->mock_funcs[i].mock_func_name = mock_func_name;
            return NULL;
        }
    }

    return astro_errorf(astro, "Out of mock functions! Used %lu/%lu",
                        mock_funcs_len, mock_funcs_len);
}

// Look up a function's address, accounting for mock functions
static const astro_err_t *_func_addr(astro_t *astro, const char *name,
                                     uint64_t *func_addr_out) {
    size_t mock_funcs_len = sizeof astro->mock_funcs / sizeof astro->mock_funcs[0];
    for (unsigned int i = 0; i < mock_funcs_len; i++) {
        if (astro->mock_funcs[i].func_name &&
                astro->mock_funcs[i].mock_func_name &&
                !strcmp(astro->mock_funcs[i].func_name, name)) {
            name = astro->mock_funcs[i].mock_func_name;
            break;
        }
    }

    const astro_err_t *astro_err;

    if (!astro_get_symbol_addr(astro, name, func_addr_out)) {
        astro_err = astro_errorf(astro, "cannot find symbol `%s'", name);
        goto failure;
    }

    return NULL;

    failure:
    return astro_err;
}

const astro_err_t *astro_call_function(astro_t *astro, uint64_t *ret, size_t n,
                                       const char *name, ...) {
    const astro_err_t *astro_err;
    uc_err err;

    if (n > sizeof ARG_REGS / sizeof *ARG_REGS) {
        astro_err = astro_errorf(astro, "unsupported number of args %lu", n);
        goto failure;
    }

    uint64_t func_addr;
    if (astro_err = _func_addr(astro, name, &func_addr))
        goto failure;

    // at the entry point, there's a halt instruction which
    // stops the simulation
    uint64_t return_address;
    if (astro_err = astro_get_entry_point_addr(astro, &return_address))
        goto failure;

    uint64_t stack_bottom = astro->mem_ctx.stack_range.high_addr - 8;

    if (err = uc_mem_write(astro->uc, stack_bottom, &return_address, 8)) {
        astro_err = astro_uc_perror(astro, "uc_mem_write return address", err);
        goto failure;
    }

    // set stack pointer
    if (err = uc_reg_write(astro->uc, UC_X86_REG_RSP, &stack_bottom)) {
        astro_err = astro_uc_perror(astro, "uc_reg_write %rsp", err);
        goto failure;
    }

    // go ahead and clear base pointer for fun
    uint64_t zero = 0;
    if (err = uc_reg_write(astro->uc, UC_X86_REG_RBP, &zero)) {
        astro_err = astro_uc_perror(astro, "uc_reg_write %rbp", err);
        goto failure;
    }

    va_list ap;
    va_start(ap, name);

    for (size_t i = 0; i < n; i++) {
        uint64_t arg = va_arg(ap, uint64_t);

        if (err = uc_reg_write(astro->uc, ARG_REGS[i], &arg)) {
            astro_err = astro_errorf(astro, "uc_reg_write arg #%lu: %s",
                                     i+1, uc_strerror(err));
            va_end(ap);
            goto failure;
        }
    }

    va_end(ap);

    astro->halted = false;
    astro->exec_err = NULL;
    astro->sim_state = ASTRO_SIM_EXEC;

    if (err = uc_emu_start(astro->uc, func_addr, 0, 0,
                           MAX_INSTRUCTION_COUNT)) {
        // Let the segfault handler take care of segfaults. It will set
        // astro->exec_err, so just return that
        if (err == UC_ERR_READ_UNMAPPED ||
            err == UC_ERR_WRITE_UNMAPPED ||
            err == UC_ERR_FETCH_UNMAPPED ||
            err == UC_ERR_WRITE_PROT ||
            err == UC_ERR_READ_PROT ||
            err == UC_ERR_FETCH_PROT)
            astro_err = astro->exec_err;
        else
            astro_err = astro_errorf(astro, "uc_emu_start %s(): %s\n", name,
                                     uc_strerror(err));

        goto failure;
    }

    astro->sim_state = ASTRO_SIM_NO;

    if (ret) {
        if (err = uc_reg_read(astro->uc, UC_X86_REG_RAX, ret)) {
            astro_err = astro_uc_perror(astro, "uc_reg_read %rax", err);
            goto failure;
        }
    }

    // error set by stubs or other listeners
    if (astro_err = astro->exec_err)
        goto failure;

    // if we didn't make it to the halt instruction, unicorn must've
    // terminated the simulation early (a timeout)
    if (!astro->halted) {
        astro_err = astro_errorf(astro, "Timeout expired. Does your code have "
                                        "an infinite loop?");
        goto failure;
    }

    failure:
    astro->sim_state = ASTRO_SIM_NO;
    return astro_err;
}

const astro_err_t *astro_make_backtrace(astro_t *astro,
                                        const astro_bt_t **bt_out,
                                        size_t *bt_len_out,
                                        bool *bt_truncated_out) {
    // No backtrace to make if we're not executing student code
    if (astro->sim_state == ASTRO_SIM_NO) {
        *bt_out = NULL;
        *bt_len_out = 0;
        *bt_truncated_out = false;
        return NULL;
    }

    astro_bt_t *bt_arr = astro->bt_mem;
    size_t bt_arr_max = sizeof astro->bt_mem / sizeof *astro->bt_mem;

    const astro_err_t *astro_err;
    uc_err err;

    // call_function() above pushes the ELF entry point onto the stack
    // before starting the simulator, since there's only a hlt at that
    // address (halting the simulator). We don't need to include that in
    // the backtrace (should be "magic" to students). So grab the entry
    // point from the ELF header, and stop printing when we hit it
    uint64_t final_return_addr;
    if (astro_err = astro_get_entry_point_addr(astro, &final_return_addr))
        goto failure;

    uint64_t base_pointer;

    if (err = uc_reg_read(astro->uc, UC_X86_REG_RBP, &base_pointer)) {
        // Prevent infinite recursion
        astro->sim_state = ASTRO_SIM_NO;
        astro_err = astro_uc_perror(astro, "uc_reg_read %%rbp for backtrace",
                                    err);
        goto failure;
    }

    uint64_t return_addr;

    if (astro->sim_state == ASTRO_SIM_STUB) {
        // If backtrace is being called from a stub, the top of the
        // stack is the return address pushed by student code. So grab
        // it off so we can use it to print the line that called
        // the stub
        uint64_t stack_top_ptr;

        if (err = uc_reg_read(astro->uc, UC_X86_REG_RSP, &stack_top_ptr)) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_uc_perror(astro, "uc_reg_read %rsp for backtrace",
                                        err);
            goto failure;
        }

        // Read return address off stack (currently the top of the stack,
        // since stubs don't touch it)
        if (err = uc_mem_read(astro->uc, stack_top_ptr, &return_addr, 8)) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "uc_mem_read address 0x%lx (%%rbp + 8) "
                                     "for backtrace: %s",
                                     stack_top_ptr, uc_strerror(err));
            goto failure;
        }
    } else {
        // If backtrace is being called in response to a student
        // whoopsie daisy, then we want to start the backtrace at %rip,
        // the PC
        if (err = uc_reg_read(astro->uc, UC_X86_REG_RIP, &return_addr)) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_uc_perror(astro,
                                        "uc_reg_read %rip for backtrace", err);
            goto failure;
        }

        // HACK: Account for the -1 in the loop below
        return_addr++;
    }

    unsigned int bt_idx = 0;
    *bt_truncated_out = false;

    // TODO: give up after n iterations (for infinite loops)
    // call_function() above sets %rbp = 0 and pushes the ELF entry
    // point onto the stack when calling a function
    while (return_addr != final_return_addr && base_pointer &&
           !(*bt_truncated_out = (bt_idx == bt_arr_max))) {
        // Back up into the last instruction: we want the instruction
        // that made the function call, not the return address
        // TODO: does this always work?
        uint64_t prev_instr_addr = return_addr - 1;

        // Find the Compilation Unit Debugging Information Entry (CU
        // DIE) corresponding to this address
        Dwarf_Die cu_die;
        if (!dwarf_addrdie(astro->dwarf, prev_instr_addr, &cu_die)) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "dwarf_addrdie for address 0x%lx for "
                                     "backtrace: %s",
                                     prev_instr_addr, dwarf_errmsg(-1));
            goto failure;
        }

        Dwarf_Die *scopes = NULL;
        int nscopes = dwarf_getscopes(&cu_die, prev_instr_addr, &scopes);
        if (nscopes <= 0) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "dwarf_getscopes for address 0x%lx: %s",
                                     prev_instr_addr,
                                     (nscopes == 0)? "no scopes found!"
                                                   : dwarf_errmsg(-1));
            free(scopes);
            goto failure;
        }

        // Search scopes for function to which this belongs
        const char *function_name = NULL;
        for (int i = 0; !function_name && i < nscopes; i++) {
            if (dwarf_tag(&scopes[i]) == DW_TAG_subprogram) {
                function_name = dwarf_diename(&scopes[i]);

                if (!function_name) {
                    // Prevent infinite recursion
                    astro->sim_state = ASTRO_SIM_NO;
                    astro_err = astro_dwarf_perror(astro, "dwarf_diename");
                    free(scopes);
                    goto failure;
                }
            }
        }

        free(scopes);

        if (!function_name) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "can't find function name for 0x%lx",
                                     prev_instr_addr);
            goto failure;
        }

        // Find the line for this address
        Dwarf_Line *line;
        if (!(line = dwarf_getsrc_die(&cu_die, prev_instr_addr))) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "dwarf_getsrc_die for address 0x%lx for "
                                     "backtrace: %s",
                                     return_addr, dwarf_errmsg(-1));
            goto failure;
        }

        const char *filename;
        if (!(filename = dwarf_linesrc(line, NULL, NULL))) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "dwarf_linesrc for address 0x%lx for "
                                     "backtrace: %s",
                                     return_addr, dwarf_errmsg(-1));
            goto failure;
        }

        int lineno;
        dwarf_lineno(line, &lineno);

        bt_arr[bt_idx].file = astro_intern_str(astro, filename);
        bt_arr[bt_idx].function = astro_intern_str(astro, function_name);
        bt_arr[bt_idx].line = lineno;
        bt_idx++;

        // Now: go to the next stack frame.
        // Saved %eip was pushed onto stack right before saved %ebp was
        uint64_t return_addr_ptr = base_pointer + 8;

        // Read return address off stack (pushed right before saved %rbp)
        if (err = uc_mem_read(astro->uc, return_addr_ptr, &return_addr, 8)) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "uc_mem_read address 0x%lx (%%rbp + 8) "
                                     "for backtrace: %s",
                                     return_addr_ptr, uc_strerror(err));
            goto failure;
        }

        if (err = uc_mem_read(astro->uc, base_pointer, &base_pointer, 8)) {
            // Prevent infinite recursion
            astro->sim_state = ASTRO_SIM_NO;
            astro_err = astro_errorf(astro,
                                     "uc_mem_read address 0x%lx (%%rbp) for "
                                     "backtrace: %s\n",
                                     base_pointer, uc_strerror(err));
            goto failure;
        }
    }

    *bt_out = astro->bt_mem;
    *bt_len_out = bt_idx;

    return NULL;

    failure:
    return astro_err;
}

static void stub_hook_callback(uc_engine *uc, uint64_t addr, uint32_t size,
                               void *user_data) {
    (void)uc;
    (void)addr;
    (void)size;

    stub_t *stub = user_data;
    stub->astro->sim_state = ASTRO_SIM_STUB;
    stub->impl(stub->astro, stub->user_data);
    stub->astro->sim_state = ASTRO_SIM_EXEC;
}

const astro_err_t *astro_stub_arg(astro_t *astro, size_t idx, uint64_t *arg_out) {
    const astro_err_t *astro_err;

    if (idx >= sizeof ARG_REGS / sizeof *ARG_REGS) {
        astro_err = astro_errorf(astro, "unsupported args index %lu", idx);
        goto failure;
    }

    uc_err err;
    if (err = uc_reg_read(astro->uc, ARG_REGS[idx], arg_out)) {
        astro_err = astro_errorf(astro, "uc_reg_read arg index %lu: %s", idx,
                                 uc_strerror(err));
        goto failure;
    }

    return NULL;

    failure:
    return astro_err;
}

const astro_err_t *astro_stub_ret(astro_t *astro, uint64_t retval) {
    uc_err err;
    if (err = uc_reg_write(astro->uc, ARG_REG_RET, &retval))
        return astro_uc_perror(astro, "uc_reg_write return value", err);

    return NULL;
}

void astro_stub_die(astro_t *astro, const astro_err_t *astro_err) {
    astro->exec_err = astro_err;

    uc_err err;
    // TODO: create some kind of chained astro_err_t
    // No way to handle this error, but print it anyway
    if (err = uc_emu_stop(astro->uc))
        fprintf(stderr, "uc_emu_stop: %s\n", uc_strerror(err));
}

const astro_err_t *astro_stub_setup(astro_t *astro, void *user_data,
                                    const char *name,
                                    astro_stub_impl_t impl) {
    const astro_err_t *astro_err;
    uint64_t func_addr;
    if (!astro_get_symbol_addr(astro, name, &func_addr)) {
        astro_err = astro_errorf(astro, "cannot find symbol `%s'", name);
        goto failure;
    }

    unsigned int i = 0;
    size_t max_stubs = sizeof astro->stubs / sizeof astro->stubs[0];
    for (; i < max_stubs && astro->stubs[i].valid; i++);

    if (i == max_stubs) {
        astro_err = astro_errorf(astro, "max number of stubs %u reached, "
                                        "can't create stub", max_stubs);
        goto failure;
    }

    stub_t *stub = &astro->stubs[i];
    stub->valid = 1;
    stub->astro = astro;
    stub->user_data = user_data;
    stub->impl = impl;

    uc_err err;
    uc_cb_hookcode_t hook_cb = stub_hook_callback;

    if (err = uc_hook_add(astro->uc, &stub->hook, UC_HOOK_CODE,
                          FP2VOID(hook_cb), stub, func_addr, func_addr)) {
        astro_err = astro_errorf(astro, "uc_hook_add for stub %s: %s", name,
                                 uc_strerror(err));
        goto failure;
    }

    return NULL;

    failure:
    return astro_err;
}
