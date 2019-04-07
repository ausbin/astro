#define STUB(name) \
    .globl name; \
    name: \
        ret

STUB(stubby)
STUB(malloc)
STUB(free)
