##
## Globals
##
CC = gcc
LD = ld
OBJDUMP = objdump
CFLAGS = -g -pedantic -Wall -Werror -Wextra \
         -Wstrict-prototypes -Wold-style-definition

.PHONY: all
all: student.elf tester

##
## Tester
##
TESTER_CFLAGS = $(CFLAGS) -pthread -std=gnu99
TESTER_HFILES = $(wildcard **/*.h)
TESTER_LIBS = -Ltester-src -lastro -lm -lz -ldl
TESTER_CFILES = $(wildcard tester-src/*.c)
TESTER_OFILES = $(patsubst %.c,%.o,$(TESTER_CFILES))

tester-src/%.o: tester-src/%.c $(HFILES)
	$(CC) -c $(TESTER_CFLAGS) $< -o $@

tester: $(TESTER_OFILES)
	$(CC) -Wl,-rpath=tester-src -o $@ $^ $(TESTER_LIBS)

##
## Student code
##
# -fno-asynchronous-unwind-tables removes the annoying .eh_frame section
# see: https://stackoverflow.com/a/26302715/321301
USER_CFLAGS = $(CFLAGS) -fno-builtin -fno-asynchronous-unwind-tables -std=c99 -Ires
USER_CFILES = $(wildcard *.c)
USER_SFILES = $(wildcard res/*.S)
USER_OFILES = $(patsubst %.c,%.o,$(USER_CFILES)) $(patsubst %.S,%.o,$(USER_SFILES))

# Make student.elf not executable so students won't try to run it on
# baremetal
student.elf res/student.asm: res/student.ld $(USER_OFILES)
	$(LD) -T res/student.ld -static -o student.elf $(USER_OFILES)
	$(OBJDUMP) -l -S student.elf >res/student.asm
	chmod -x student.elf

%.o: %.c $(HFILES)
	$(CC) -c $(USER_CFLAGS) $< -o $@

%.o: res/%.S $(HFILES)
	$(CC) -c $(USER_CFLAGS) $< -o $@

clean:
	rm -f tester *.elf res/*.asm *.o **/*.o
