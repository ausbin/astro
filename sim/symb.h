#include <stdint.h>
#include <stdio.h>

#define NAME_MAX_LEN 32
#define HASH_TABLE_LEN 23

typedef struct symb_section {
    uint64_t start_addr;
    uint64_t length;
    char name[NAME_MAX_LEN];
    struct symb_section *next;
} symb_section;

typedef struct symb_symbol {
    uint64_t addr;
    char name[NAME_MAX_LEN];
    struct symb_symbol *next;
} symb_symbol;

typedef struct symb {
    symb_section *sections[HASH_TABLE_LEN];
    symb_symbol *symbols[HASH_TABLE_LEN];
} symb;

extern symb *symb_new(void);
extern void symb_free(symb *s);
extern symb *symb_load(FILE *symbfp);
extern symb_section *symb_get_section(symb *sym, const char *name);
extern symb_symbol *symb_get_symbol(symb *sym, const char *name);
