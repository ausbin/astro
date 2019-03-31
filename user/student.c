int fib(int n) {
    // TODO: try this using DP instead
    if (n == 0 || n == 1)
        return n;
    return fib(n - 1) + fib(n - 2);
}
