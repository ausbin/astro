#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include <libelf.h>
#include <gelf.h>

// TODO: figure out how to grow these
#define HEAP_STACK_SIZE 0x2000

static int load_sections(uc_engine *uc, Elf *elf) {
    uc_err err;

    // 4K of zeros, for writing to memory
    char *zeros = calloc(1, 0x1000);
    if (!zeros) {
        perror("calloc");
        goto failure;
    }

    Elf_Scn *scn = NULL;

    // the section number of the ELF string section
    size_t shdrstrndx;

    if (elf_getshdrstrndx(elf, &shdrstrndx)) {
        fprintf(stderr, "elf_getshdrstrndx: %s\n", elf_errmsg(-1));
        goto failure;
    }

    while (scn = elf_nextscn(elf, scn)) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "elf_getshdr: %s\n", elf_errmsg(-1));
            goto failure;
        }

        const char *section_name = elf_strptr(elf, shdrstrndx, shdr.sh_name);

        if (!section_name) {
            fprintf(stderr, "elf_strptr: %s\n", elf_errmsg(-1));
            goto failure;
        }

        if (strcmp(section_name, ".text") &&
            strcmp(section_name, ".data") &&
            strcmp(section_name, ".bss"))
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);

        if (!data) {
            fprintf(stderr, "elf_getdata: %s\n", elf_errmsg(-1));
            goto failure;
        }

        uint32_t perms;

        if (!strcmp(section_name, ".text"))
            perms = UC_PROT_READ | UC_PROT_EXEC;
        else if (!strcmp(section_name, ".data") || !strcmp(section_name, ".bss"))
            perms = UC_PROT_READ | UC_PROT_WRITE;
        else {
            fprintf(stderr, "unrecognized section `%s'\n", section_name);
            goto failure;
        }

        uint64_t length_rounded = (shdr.sh_size + 0xFFF) & ~0xFFF;

        if (err = uc_mem_map(uc, shdr.sh_addr, length_rounded, perms)) {
            fprintf(stderr, "uc_mem_map section %s: %s\n", section_name,
                    uc_strerror(err));
            goto failure;
        }

        if (!strcmp(section_name, ".bss")) {
            for (uint64_t addr = shdr.sh_addr;
                 addr < shdr.sh_addr + length_rounded;
                 addr += 0x1000) {
                if (err = uc_mem_write(uc, addr, zeros, 0x1000)) {
                    fprintf(stderr, "uc_mem_write %s: %s\n", section_name,
                            uc_strerror(err));
                    goto failure;
                }
            }
        } else {
            if (err = uc_mem_write(uc, shdr.sh_addr, data->d_buf, shdr.sh_size)) {
                fprintf(stderr, "uc_mem_write %s: %s\n", section_name,
                        uc_strerror(err));
                goto failure;
            }

            if (shdr.sh_size < length_rounded) {
                if (err = uc_mem_write(uc, shdr.sh_addr + shdr.sh_size, zeros,
                                       length_rounded - shdr.sh_size)) {
                    fprintf(stderr, "uc_mem_write zero padding for %s: %s\n",
                            section_name, uc_strerror(err));
                    goto failure;
                }
            }
        }
    }

    free(zeros);
    return 1;

    failure:
    free(zeros);
    return 0;
}

static int get_symbol_addr(Elf *elf, const char *needle_name, uint64_t *addr_out) {
    // the section number of the ELF string section
    size_t shdrstrndx;

    // Grab the section index of the section header string table. This
    // is NOT the string table, so we know to skip it
    if (elf_getshdrstrndx(elf, &shdrstrndx)) {
        fprintf(stderr, "elf_getshdrstrndx: %s\n", elf_errmsg(-1));
        goto failure;
    }

    Elf_Scn *scn = NULL;
    Elf_Scn *strtab_scn = NULL;
    size_t strtab_idx;

    // Look for a string table section
    while (scn = elf_nextscn(elf, scn)) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "gelf_getshdr: %s\n", elf_errmsg(-1));
            goto failure;
        }

        strtab_idx = elf_ndxscn(scn);

        if (shdr.sh_type == SHT_STRTAB && shdrstrndx != strtab_idx) {
            strtab_scn = scn;
            break;
        }
    }

    if (!strtab_scn) {
        fprintf(stderr, "did not find a strtable in the file!\n");
        goto failure;
    }

    scn = NULL;

    // Look for a symbol table section
    while (scn = elf_nextscn(elf, scn)) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "gelf_getshdr: %s\n", elf_errmsg(-1));
            goto failure;
        }

        if (shdr.sh_type != SHT_SYMTAB)
            continue;


        Elf_Data *data = elf_getdata(scn, NULL);

        if (!data) {
            fprintf(stderr, "elf_getdata: %s\n", elf_errmsg(-1));
            goto failure;
        }

        const uint64_t num_symbols = shdr.sh_size / shdr.sh_entsize;

        for (uint64_t i = 0; i < num_symbols; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, i, &sym)) {
                fprintf(stderr, "gelf_getsym: %s\n", elf_errmsg(-1));
                goto failure;
            }

            const char *symb_name = elf_strptr(elf, strtab_idx, sym.st_name);
            if (!symb_name) {
                fprintf(stderr, "elf_strptr: %s\n", elf_errmsg(-1));
                goto failure;
            }

            if ((GELF_ST_TYPE(sym.st_info) == STT_NOTYPE ||
                 GELF_ST_TYPE(sym.st_info) == STT_OBJECT ||
                 GELF_ST_TYPE(sym.st_info) == STT_FUNC) &&
                GELF_ST_BIND(sym.st_info) == STB_GLOBAL &&
                !strcmp(symb_name, needle_name)) {
                *addr_out = sym.st_value;
                return 1;
            }
        }
    }

    failure:
    return 0;
}

// Return the address of the bottom of the stack or 0 on failure
static int setup_stack_heap(uc_engine *uc, Elf *elf) {
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

static int get_entry_point_addr(Elf *elf, uint64_t *addr_out) {
    GElf_Ehdr elf_header;
    if (!gelf_getehdr(elf, &elf_header)) {
        fprintf(stderr, "gelf_getehdr: %s\n", elf_errmsg(-1));
        return 0;
    }
    *addr_out = elf_header.e_entry;
    return 1;
}

static int call_function(uc_engine *uc, Elf *elf, uint64_t stack_bottom,
                         uint64_t *ret, size_t n, const char *name, ...) {
    static const int ARG_REGS[] = {
        UC_X86_REG_RDI,
        UC_X86_REG_RSI,
        UC_X86_REG_RDX,
        UC_X86_REG_RCX,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
    };
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

    if (err = uc_reg_read(uc, UC_X86_REG_RAX, ret)) {
        fprintf(stderr, "uc_reg_read %%rax: %s\n", uc_strerror(err));
        goto failure;
    }

    return 1;

    failure:
    return 0;
}

int main(void) {
    uc_engine *uc;
    uc_err err;

    FILE *binfp = fopen("student.elf", "r");
    if (!binfp) {
        perror("fopen");
        return 0;
    }

    // hi libelf, i'm using the current version!
    elf_version(EV_CURRENT);

    Elf *elf = elf_begin(fileno(binfp), ELF_C_READ_MMAP, NULL);

    if (!elf) {
        fprintf(stderr, "elf_begin: %s\n", elf_errmsg(-1));
        fclose(binfp);
        return 0;
    }

    if (err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc)) {
        fprintf(stderr, "uc_open: %s\n", uc_strerror(err));
        goto failure;
    }

    if (!load_sections(uc, elf))
        goto failure;

    uint64_t stack_bottom = setup_stack_heap(uc, elf);

    if (!stack_bottom)
        goto failure;

    for (uint64_t i = 0; i <= 32; i++) {
        uint64_t ret;
        if (!call_function(uc, elf, stack_bottom, &ret, 1,
                           "fib", i))
            goto failure;

        printf("fib(%lu): %lu\n", i, ret);
    }

    elf_end(elf);
    fclose(binfp);
    uc_close(uc);

    return 0;

    failure:
    elf_end(elf);
    fclose(binfp);
    uc_close(uc);

    return 1;
}
