#define STUB(name) \
    .globl name; \
    name: \
        ret

// These are stubbed out by the astro library automatically
STUB(malloc)
STUB(calloc)
STUB(realloc)
STUB(free)

// Defined inside the tester
STUB(__backtrace)
