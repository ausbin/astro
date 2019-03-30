#include "sbrk.h"

// In linker script
extern char *const __heap_start;

static char *break_addr;

void *sbrk(intptr_t incr) {
    if (!break_addr)
        break_addr = __heap_start;

    void *ret = break_addr;
    break_addr += incr;
    return ret;
}
