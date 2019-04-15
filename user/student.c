#include <stdint.h>
#include "stubs.h"

static void magic_inline(void) {
    __asm__("nop\n");
    stubby(*(char *)0x32);
}

int fib(int n) {
    // TODO: try this using DP instead
    if (n == 0 || n == 1)
        return n;
    return fib(n - 1) + fib(n - 2);
}

void stupid(int n) {
    uint64_t ret = (uint64_t) malloc(0x800 - 64);
    //stubby(ret);
    if (n)
        stupid(n-1);
    else {
        stubby(0x69);
        magic_inline();
        //backtrace();
    }
    free((void *) ret);
}

void asdf(void) {
    stupid(10);
}
