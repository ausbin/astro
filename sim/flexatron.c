#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

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
    FILE *symbfp = fopen("student.sym", "r");
    if (!symbfp) {
        perror("fopen");
        return 1;
    }

    struct symb *head = load_symb(symbfp);

    if (!head) {
        fclose(symbfp);
        return 1;
    }

    for (struct symb *n = head; n; n = n->next) {
        if (n->section) {
            printf("section .%s at 0x%lx, length 0x%lx\n", n->name, n->start_addr, n->length);
        } else {
            printf("symbol %s at 0x%lx\n", n->name, n->start_addr);
        }
    }

    free_symb_list(head);
    fclose(symbfp);

    //uc_engine *uc;
    //uc_err err;

    //if (err = uc_open(UC_ARCH_X86, UC_MODE_64)) {
    //    fprintf(stderr, "uc_open: %u\n", err);
    //    return 1;
    //}

    ////uc_mem_map(uc, LOAD_ADDR, MEM_SIZE, );

    //uc_close(uc);

    return 0;
}
