#include <stdio.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include <libelf.h>
#include <elfutils/libdw.h>
#include <gelf.h>
#include "defs.h"

const astro_err_t *astro_open_elf(astro_t *astro, const char *filename,
                                  FILE **fp_out, Elf **elf_out,
                                  Dwarf **dwarf_out) {
    const astro_err_t *astro_err = NULL;
    Elf *elf = NULL;

    FILE *binfp = fopen(filename, "r");
    if (!binfp) {
        astro_err = astro_perror(astro, "fopen elf");
        goto failure;
    }

    // hi libelf, i'm using the current version!
    elf_version(EV_CURRENT);

    elf = elf_begin(fileno(binfp), ELF_C_READ_MMAP, NULL);

    if (!elf)
        return astro_elf_perror(astro, "elf_begin");

    Dwarf *dwarf = dwarf_begin_elf(elf, DWARF_C_READ, NULL);

    if (!elf) {
        astro_err = astro_dwarf_perror(astro, "dwarf_begin_elf");
        goto failure;
    }

    *fp_out = binfp;
    *elf_out = elf;
    *dwarf_out = dwarf;

    return NULL;

    failure:
    if (elf)
        elf_end(elf);
    if (binfp)
        fclose(binfp);
    return astro_err;
}

const astro_err_t *astro_get_entry_point_addr(astro_t *astro,
                                              uint64_t *addr_out) {
    GElf_Ehdr elf_header;
    if (!gelf_getehdr(astro->elf, &elf_header)) {
        return astro_elf_perror(astro, "gelf_getehdr");
    }
    *addr_out = elf_header.e_entry;
    return NULL;
}

const astro_err_t *astro_load_sections(astro_t *astro) {
    const astro_err_t *astro_err = NULL;
    uc_err err;
    Elf_Scn *scn = NULL;

    // the section number of the ELF section header string section
    size_t shdrstrndx;

    if (elf_getshdrstrndx(astro->elf, &shdrstrndx)) {
        astro_err = astro_elf_perror(astro, "elf_getshdrstrndx");
        goto failure;
    }

    while (scn = elf_nextscn(astro->elf, scn)) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            astro_err = astro_elf_perror(astro, "elf_getshdr");
            goto failure;
        }

        const char *section_name = elf_strptr(astro->elf, shdrstrndx,   
                                              shdr.sh_name);

        if (!section_name) {
            astro_err = astro_elf_perror(astro, "elf_strptr");
            goto failure;
        }

        if (strcmp(section_name, ".text") &&
            strcmp(section_name, ".data") &&
            strcmp(section_name, ".bss"))
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);

        if (!data) {
            astro_err = astro_elf_perror(astro, "elf_getdata");
            goto failure;
        }

        uint32_t perms;

        if (!strcmp(section_name, ".text"))
            perms = UC_PROT_READ | UC_PROT_EXEC;
        else if (!strcmp(section_name, ".data") || !strcmp(section_name, ".bss"))
            perms = UC_PROT_READ | UC_PROT_WRITE;
        else {
            astro_err = astro_errorf(astro, "unrecognized section `%s'", section_name);
            goto failure;
        }

        uint64_t length_rounded = ROUND_TO_4K(shdr.sh_size);

        if (err = uc_mem_map(astro->uc, shdr.sh_addr, length_rounded, perms)) {
            astro_err = astro_errorf(astro, "uc_mem_map section %s: %s",
                                     section_name, uc_strerror(err));
            goto failure;
        }

        if (!strcmp(section_name, ".bss")) {
            for (uint64_t addr = shdr.sh_addr;
                 addr < shdr.sh_addr + length_rounded;
                 addr += 0x1000) {
                if (err = uc_mem_write(astro->uc, addr, four_kb_of_zeros,
                                       0x1000)) {
                    astro_err = astro_errorf(astro, "uc_mem_write section %s: %s",
                                             section_name, uc_strerror(err));
                    goto failure;
                }
            }
        } else {
            if (err = uc_mem_write(astro->uc, shdr.sh_addr, data->d_buf,
                                   shdr.sh_size)) {
                astro_err = astro_errorf(astro, "uc_mem_write section %s: %s",
                                         section_name, uc_strerror(err));
                goto failure;
            }

            if (shdr.sh_size < length_rounded) {
                if (err = uc_mem_write(astro->uc, shdr.sh_addr + shdr.sh_size,
                                       four_kb_of_uninit,
                                       length_rounded - shdr.sh_size)) {
                    astro_err = astro_errorf(astro, "uc_mem_write zero padding for %s: %s",
                                             section_name, uc_strerror(err));
                    goto failure;
                }
            }
        }
    }

    return NULL;

    failure:
    return astro_err;
}

int astro_get_symbol_addr(astro_t *astro, const char *needle_name,
                          uint64_t *addr_out) {
    // the section number of the ELF string section
    size_t shdrstrndx;

    // Grab the section index of the section header string table. This
    // is NOT the string table, so we know to skip it
    if (elf_getshdrstrndx(astro->elf, &shdrstrndx)) {
        fprintf(stderr, "elf_getshdrstrndx: %s\n", elf_errmsg(-1));
        goto failure;
    }

    Elf_Scn *scn = NULL;
    Elf_Scn *strtab_scn = NULL;
    size_t strtab_idx;

    // Look for a string table section
    while (scn = elf_nextscn(astro->elf, scn)) {
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
    while (scn = elf_nextscn(astro->elf, scn)) {
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

            const char *symb_name = elf_strptr(astro->elf, strtab_idx,
                                               sym.st_name);
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
