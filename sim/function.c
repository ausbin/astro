#include <unicorn/unicorn.h>
#include <libelf.h>
#include "defs.h"

// Contains code for calling/stubbing functions

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

// Return the address of the bottom of the stack or 0 on failure
int setup_stack_heap(uc_engine *uc, Elf *elf) {
    uc_err err;
    char *zeros = NULL;

    // Now, need to setup stack and heap -- allocate 8K for each
    // Put heap right where __heap_start is (from linker script)
    uint64_t heap_start_addr;
    if (!get_symbol_addr(elf, "__heap_start", &heap_start_addr)) {
        fprintf(stderr, "where is my __heap_start symbol?\n");
        goto failure;
    }

    zeros = calloc(1, HEAP_STACK_SIZE);
    if (!zeros) {
        perror("calloc");
        goto failure;
    }

    // setup heap
    uint64_t addr = heap_start_addr;
    if (err = uc_mem_map(uc, addr, HEAP_STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map heap: %s\n", uc_strerror(err));
        goto failure;
    }
    if (err = uc_mem_write(uc, addr, zeros, HEAP_STACK_SIZE)) {
        fprintf(stderr, "uc_mem_write heap: %s\n", uc_strerror(err));
        free(zeros);
        goto failure;
    }

    addr += HEAP_STACK_SIZE;
    // 4K guard page against geniuses
    addr += 0x1000;

    // now setup stack
    if (err = uc_mem_map(uc, addr, HEAP_STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)) {
        fprintf(stderr, "uc_mem_map stack: %s\n", uc_strerror(err));
        goto failure;
    }
    if (err = uc_mem_write(uc, addr, zeros, HEAP_STACK_SIZE)) {
        fprintf(stderr, "uc_mem_write stack: %s\n", uc_strerror(err));
        goto failure;
    }

    // Move to bottom of the stack
    addr += HEAP_STACK_SIZE - 8;

    free(zeros);
    return addr;

    failure:
    free(zeros);
    return 0;
}

static void stubby_hook(uc_engine *uc, uint64_t addr, uint32_t size,
                        void *user_data) {
    (void)addr;
    (void)size;
    (void)user_data;

    uc_err err;
    uint64_t ret;

    if (err = uc_reg_read(uc, UC_X86_REG_RDI, &ret)) {
        fprintf(stderr, "uc_reg_read %%rdi: %s\n", uc_strerror(err));
        // TODO: bail somehow?
    }

    printf("stubby hit! n = %lu\n", ret);
}

int setup_hooks(uc_engine *uc, Elf *elf) {
    uint64_t stubby_addr;
    if (!get_symbol_addr(elf, "stubby", &stubby_addr)) {
        fprintf(stderr, "cannot find symbol `stubby'\n");
        goto failure;
    }

    uc_err err;
    uc_hook hook;

    uc_cb_hookcode_t hook_cb = stubby_hook;

    if (err = uc_hook_add(uc, &hook, UC_HOOK_CODE, *((void **) &hook_cb), NULL,
                          stubby_addr, stubby_addr)) {
        fprintf(stderr, "uc_hook_add: %s\n", uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}

