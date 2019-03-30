#include <stdlib.h>
#include <string.h>
#include "symb.h"

// print('\n'.join(['    {}UL, // 31^{}'.format(31**i % 2**64, i) for i in reversed(range(31))]))
const uint64_t name_hash_exp_lut[] = {
    8776101465919375425UL, // 31^30
    3853437609941183391UL, // 31^29
    16785879731413181569UL, // 31^28
    5301930074873857887UL, // 31^27
    7906761388164452545UL, // 31^26
    7990788204722213663UL, // 31^25
    13349005091172011265UL, // 31^24
    11141625755417546463UL, // 31^23
    2144576063759554881UL, // 31^22
    5424686217004694175UL, // 31^21
    770046138410136961UL, // 31^20
    16686415490396051039UL, // 31^19
    12439396676277002689UL, // 31^18
    5161720944063013407UL, // 31^17
    12662688596514954753UL, // 31^16
    1003530086136274399UL, // 31^15
    627428198704704065UL, // 31^14
    5970802223735490975UL, // 31^13
    787662783788549761UL, // 31^12
    25408476896404831UL, // 31^11
    819628286980801UL, // 31^10
    26439622160671UL, // 31^9
    852891037441UL, // 31^8
    27512614111UL, // 31^7
    887503681UL, // 31^6
    28629151UL, // 31^5
    923521UL, // 31^4
    29791UL, // 31^3
    961UL, // 31^2
    31UL, // 31^1
    1UL, // 31^0
};

static uint64_t hash_name(const char *name) {
    uint64_t hash = 0;

    for (int i = 0; name[i]; i++)
        hash += name_hash_exp_lut[i] * name[i];

    return hash % HASH_TABLE_LEN;
}

symb *symb_new(void) {
    symb *s = malloc(sizeof (symb));

    if (!s) {
        perror("malloc");
        return NULL;
    }

    memset(s, 0, sizeof (symb));
    return s;
}

symb_section *symb_get_section(symb *sym, const char *name) {
    if (!sym)
        return NULL;

    for (symb_section *head = sym->sections[hash_name(name)]; head; head = head->next)
        if (!strcmp(head->name, name))
            return head;

    return NULL;
}

symb_symbol *symb_get_symbol(symb *sym, const char *name) {
    if (!sym)
        return NULL;

    for (symb_symbol *head = sym->symbols[hash_name(name)]; head; head = head->next)
        if (!strcmp(head->name, name))
            return head;

    return NULL;
}

static symb_symbol *symbol_new(void) {
    symb_symbol *s = malloc(sizeof (symb_symbol));

    if (!s) {
        perror("malloc");
        return NULL;
    }

    memset(s, 0, sizeof (symb_symbol));
    return s;
}

static void symbol_free_all(symb_symbol *sym) {
    while (sym) {
        symb_symbol *next = sym->next;
        free(sym);
        sym = next;
    }
}

static symb_section *section_new(void) {
    symb_section *s = malloc(sizeof (symb_section));

    if (!s) {
        perror("malloc");
        return NULL;
    }

    memset(s, 0, sizeof (symb_section));
    return s;
}

static void section_free_all(symb_section *sec) {
    while (sec) {
        symb_section *next = sec->next;
        free(sec);
        sec = next;
    }
}

void symb_free(symb *s) {
    if (!s)
        return;

    for (int i = 0; i < HASH_TABLE_LEN; i++) {
        section_free_all(s->sections[i]);
        s->sections[i] = NULL;

        symbol_free_all(s->symbols[i]);
        s->symbols[i] = NULL;
    }

    free(s);
}

static void symb_push_section(symb *sym, symb_section *section) {
    uint64_t hash = hash_name(section->name);
    symb_section *head = sym->sections[hash];
    sym->sections[hash] = section;
    section->next = head;
}

static void symb_push_symbol(symb *sym, symb_symbol *symbol) {
    uint64_t hash = hash_name(symbol->name);
    symb_symbol *head = sym->symbols[hash];
    sym->symbols[hash] = symbol;
    symbol->next = head;
}

static int parse_name(char next, char *name, char **bpp, size_t *lenp) {
    unsigned int i = 0;
    while (*lenp && i < NAME_MAX_LEN - 1 && **bpp != next) {
        name[i] = **bpp;
        (*bpp)++;
        (*lenp)--;
        i++;
    }
    name[i] = '\0';
    if (!lenp || **bpp != next)
        return 0;
    (*bpp)++;
    (*lenp)--;

    return 1;
}

static int parse_hex(char next, uint64_t *hexp, char **bpp, size_t *lenp) {
    if (*lenp < 2 || (*bpp)[0] != '0' || (*bpp)[1] != 'x')
        return 0;

    // skip 0x
    *bpp += 2;
    *lenp -= 2;

    uint64_t hex = 0;
    while (*lenp && (**bpp >= 'a' && **bpp <= 'f' || **bpp >= 'A' && **bpp <= 'F' || **bpp >= '0' && **bpp <= '9')) {

        hex = (hex << 4) + ((**bpp >= 'a')? **bpp - 'a' + 10 : (**bpp >= 'A')? **bpp - 'A' + 10 : **bpp - '0');
        (*bpp)++;
        (*lenp)--;
    }
    if (!*lenp || **bpp != next)
        return 0;
    (*bpp)++;
    (*lenp)--;

    *hexp = hex;

    return 1;
}

symb *symb_load(FILE *symbfp) {
    char buf[128];
    int lineno = 1;
    struct symb *sym = symb_new();

    if (!sym)
        return NULL;

    symb_section *section = NULL;
    symb_symbol *symbol = NULL;

    while (fgets(buf, sizeof buf, symbfp)) {
        if (!strchr(buf, '\n')) {
            fprintf(stderr, "line %d of symbol table exceeds %lu bytes\n", lineno, sizeof (buf));
            symb_free(sym);
            return NULL;
        }

        char *bp = buf;
        size_t len = strlen(buf);

        // section
        if (len >= 1 && bp[0] == '.') {
            // skip .
            bp++;
            len--;

            section = section_new();
            if (!section)
                goto bad_anything;

            if (!parse_name(' ', section->name, &bp, &len))
                goto bad_format;

            if (!parse_hex(' ', &section->start_addr, &bp, &len))
                goto bad_format;

            if (!parse_hex('\n', &section->length, &bp, &len))
                goto bad_format;

            if (len)
                goto bad_format;

            symb_push_section(sym, section);
            section = NULL;
        } else if (len >= 2 && bp[0] == '0' && bp[1] == 'x') {
            symbol = symbol_new();
            if (!symbol)
                goto bad_anything;

            if (!parse_hex(' ', &symbol->addr, &bp, &len))
                goto bad_format;

            if (!parse_name('\n', symbol->name, &bp, &len))
                goto bad_format;

            if (len)
                goto bad_format;

            symb_push_symbol(sym, symbol);
            symbol = NULL;
        } else
            goto bad_format;

        lineno++;
    }

    if (!feof(symbfp)) {
        perror("fgets");
        goto bad_anything;
    }

    return sym;

    bad_format:
    fprintf(stderr, "line %d of symbol table is of unknown format\n", lineno);
    bad_anything:
    if (section)
        section_free_all(section);
    if (symbol)
        symbol_free_all(symbol);
    symb_free(sym);
    return NULL;
}
