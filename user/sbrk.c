#include "sbrk.h"

#define SBRK_START_ADDR ((char *) 0x10000UL)

static char *break_addr = SBRK_START_ADDR;

void *sbrk(intptr_t incr) {
    return break_addr += incr;
}
