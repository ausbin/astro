#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

#define START_ADDR 0x3000

struct symb {
    bool section;
    uint64_t start_addr;
    uint64_t length;
    char name[32];
    struct symb *next;
};

void free_symb_list(struct symb *head) {
    while (head) {
        struct symb *next = head->next;
        free(head);
        head = next;
    }
}

struct symb *load_symb(FILE *symbfp) {
    char buf[128];
    int lineno = 1;
    struct symb *head = NULL;

    while (fgets(buf, sizeof buf, symbfp)) {
        if (!strchr(buf, '\n')) {
            fprintf(stderr, "line %d of symbol table exceeds %lu bytes\n", lineno, sizeof (buf));
            free_symb_list(head);
            return NULL;
        }

        char *bp = buf;
        size_t len = strlen(buf);
        struct symb symb;

        // section
        if (len >= 1 && bp[0] == '.') {
            // skip .
            bp++;
            len--;

            unsigned int i = 0;
            while (len && i < sizeof (symb.name) - 1 && *bp != ' ') {
                symb.name[i] = *bp;
                bp++;
                len--;
                i++;
            }
            symb.name[i] = '\0';
            if (!len || *bp != ' ')
                goto bad_format;
            bp++;
            len--;

            if (len < 2 || bp[0] != '0' || bp[1] != 'x')
                goto bad_format;

            // skip 0x
            bp += 2;
            len -= 2;

            uint64_t addr = 0;
            while (len && (*bp >= 'a' && *bp <= 'f' || *bp >= 'A' && *bp <= 'F' || *bp >= '0' && *bp <= '9')) {
                addr = (addr << 4) + ((*bp >= 'a')? *bp - 'a' + 10 : (*bp >= 'A')? *bp - 'A' + 10 : *bp - '0');
                bp++;
                len--;
            }
            if (!len || *bp != ' ')
                goto bad_format;
            bp++;
            len--;

            if (len < 2 || bp[0] != '0' || bp[1] != 'x')
                goto bad_format;

            // skip 0x
            bp += 2;
            len -= 2;

            uint64_t length = 0;
            while (len && (*bp >= 'a' && *bp <= 'f' || *bp >= 'A' && *bp <= 'F' || *bp >= '0' && *bp <= '9')) {
                length = (length << 4) + ((*bp >= 'a')? *bp - 'a' + 10 : (*bp >= 'A')? *bp - 'A' + 10 : *bp - '0');
                bp++;
                len--;
            }
            if (!len || *bp != '\n')
                goto bad_format;
            bp++;
            len--;
            if (len)
                goto bad_format;

            symb.section = true;
            symb.start_addr = addr;
            symb.length = length;
            symb.next = NULL;
        } else if (len >= 2 && bp[0] == '0' && bp[1] == 'x') {
            // skip 0x
            bp += 2;
            len -= 2;

            uint64_t addr = 0;
            while (len && (*bp >= 'a' && *bp <= 'f' || *bp >= 'A' && *bp <= 'F' || *bp >= '0' && *bp <= '9')) {
                addr = (addr << 4) + ((*bp >= 'a')? *bp - 'a' + 10 : (*bp >= 'A')? *bp - 'A' + 10 : *bp - '0');
                bp++;
                len--;
            }
            if (!len || *bp != ' ')
                goto bad_format;
            bp++;
            len--;

            unsigned int i = 0;
            while (len && i < sizeof (symb.name) - 1 && *bp != '\n') {
                symb.name[i] = *bp;
                bp++;
                len--;
                i++;
            }
            symb.name[i] = '\0';
            if (!len || *bp != '\n')
                goto bad_format;
            bp++;
            len--;
            if (len)
                goto bad_format;

            symb.section = false;
            symb.start_addr = addr;
            symb.next = NULL;
        } else
            goto bad_format;

        struct symb *symb_heap = malloc(sizeof (struct symb));

        if (!symb_heap) {
            perror("malloc");
            free_symb_list(head);
            return NULL;
        }

        memcpy(symb_heap, &symb, sizeof (struct symb));
        symb_heap->next = head;
        head = symb_heap;

        lineno++;
    }

    if (!feof(symbfp)) {
        perror("fgets");
        free_symb_list(head);
        return NULL;
    }

    return head;

    bad_format:
    fprintf(stderr, "line %d of symbol table is of unknown format\n", lineno);
    free_symb_list(head);
    return NULL;
}

int main(void) {
    uc_engine *uc;
    uc_err err;

    FILE *symbfp = fopen("student.sym", "r");
    if (!symbfp) {
        perror("fopen");
        return 1;
    }

    struct symb *head = load_symb(symbfp);
    fclose(symbfp);

    if (!head) {
        return 1;
    }

    if (err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc)) {
        fprintf(stderr, "uc_open: %s\n", uc_strerror(err));
        return 1;
    }

    FILE *binfp = fopen("student.bin", "r");
    if (!binfp) {
        perror("fopen");
        free_symb_list(head);
        uc_close(uc);
        return 1;
    }

    char *binbuf = NULL;

    for (struct symb *s = head; s; s = s->next) {
        if (!s->section)
            continue;

        uint32_t perms;

        if (!strcmp(s->name, "text"))
            perms = UC_PROT_READ | UC_PROT_EXEC;
        else if (!strcmp(s->name, "data") || !strcmp(s->name, "bss"))
            perms = UC_PROT_READ | UC_PROT_WRITE;
        else {
            fprintf(stderr, "unrecognized section `%s'\n", s->name);
            fclose(binfp);
            free_symb_list(head);
            uc_close(uc);
            return 1;
        }

        if (err = uc_mem_map(uc, s->start_addr, s->length, perms)) {
            fprintf(stderr, "uc_mem_map: %s\n", uc_strerror(err));
            return 1;
        }

        char *new_binbuf = realloc(binbuf, s->length);
        if (!new_binbuf) {
            perror("realloc");
            fclose(binfp);
            free_symb_list(head);
            uc_close(uc);
            return 1;
        }
        binbuf = new_binbuf;

        if (!strcmp(s->name, "bss")) {
            memset(binbuf, 0, s->length);
        } else {
            if (fseek(binfp, s->start_addr - START_ADDR, SEEK_SET) < 0) {
                perror("fseek");
                free(binbuf);
                fclose(binfp);
                free_symb_list(head);
                uc_close(uc);
                return 1;
            }

            if (fread(binbuf, 1, s->length, binfp) < s->length) {
                if (feof(binfp)) {
                    fprintf(stderr, "fread: short read\n");
                } else {
                    perror("fread");
                }

                free(binbuf);
                fclose(binfp);
                free_symb_list(head);
                uc_close(uc);
                return 1;
            }
        }

        if (err = uc_mem_write(uc, s->start_addr, binbuf, s->length)) {
            fprintf(stderr, "uc_mem_write: %s\n", uc_strerror(err));
            return 1;
        }
    }

    // TODO:
    // 1. start at the address of the function being tested
    // 2. add heap to linker script, map accordingly
    // 3. add stack to linker script, map accordingly
    // 4. align sections in linker script to 4K
    //    see: ALIGN in
    //    https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/4/html/Using_ld_the_GNU_Linker/expressions.html
    // 5. round lengths up to 4K when mapping. zero out the difference
    //    so we behave completely deterministically
    if (err = uc_emu_start(uc, START_ADDR, 0, 0, 0)) {
        fprintf(stderr, "uc_emu_start: %s\n", uc_strerror(err));
        return 1;
    }

    free(binbuf);
    fclose(binfp);
    free_symb_list(head);
    uc_close(uc);

    return 0;
}
