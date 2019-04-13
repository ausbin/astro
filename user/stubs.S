#define STUB(name) \
    .globl name; \
    name: \
        ret

STUB(stubby)
STUB(backtrace)
STUB(malloc)
STUB(free)
