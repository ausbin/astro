#include "stubs.h"

int fib(int n) {
    // TODO: try this using DP instead
    if (n == 0 || n == 1)
        return n;
    return fib(n - 1) + fib(n - 2);
}

void asdf(void) {
    for (int i = 0; i < 16; i++) {
        stubby(i);
    }
}
