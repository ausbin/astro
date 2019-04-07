#ifndef DEFS_H
#define DEFS_H

#include <unicorn/unicorn.h>
#include <libelf.h>

// TODO: figure out how to grow these
#define HEAP_STACK_SIZE 0x2000

// elf.c
int open_elf(const char *filename, FILE **fp_out, Elf **elf_out);
int get_entry_point_addr(Elf *elf, uint64_t *addr_out);
int load_sections(uc_engine *uc, Elf *elf);
int get_symbol_addr(Elf *elf, const char *needle_name, uint64_t *addr_out);

// function.c
int call_function(uc_engine *uc, Elf *elf, uint64_t stack_bottom,
                  uint64_t *ret, size_t n, const char *name, ...);
int setup_stack_heap(uc_engine *uc, Elf *elf);
int setup_hooks(uc_engine *uc, Elf *elf);

#endif
