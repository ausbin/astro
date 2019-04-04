AS = as
CC = gcc
LD = ld
CFLAGS = -g -std=c99 -pedantic -Wall -Werror -Wextra \
         -Wno-parentheses -Wstrict-prototypes -Wold-style-definition
HFILES = $(wildcard **/*.h)

# -fno-asynchronous-unwind-tables removes the annoying .eh_frame section
# see: https://stackoverflow.com/a/26302715/321301
USER_CFLAGS = $(CFLAGS) -fno-builtin -fno-asynchronous-unwind-tables
USER_CFILES = $(wildcard user/*.c)
USER_SFILES = $(wildcard user/*.S)
USER_OFILES = $(patsubst %.c,%.o,$(USER_CFILES)) $(patsubst %.S,%.o,$(USER_SFILES))

SIM_CFLAGS = $(CFLAGS) -pthread
SIM_LIBS = $(shell pkg-config --libs unicorn)
SIM_CFILES = $(wildcard sim/*.c)
SIM_OFILES = $(patsubst %.c,%.o,$(SIM_CFILES))

.PHONY: all student clean

all: student flexatron

student: student.bin student.sym

student.bin student.elf student.map student.asm: student.ld $(USER_OFILES)
	$(LD) -T student.ld -Map=student.map -static -o student.elf $(USER_OFILES)
	objdump -l -S student.elf >student.asm
	objcopy -O binary student.elf student.bin

# Produce a simpler symbol table file
student.sym: student.map
	grep -E '(^\.(text|bss|data))|(^[[:space:]]+0x[[:alnum:]]+[[:space:]]+[a-zA-Z_]+([[:space:]]+=.*)?$$)' $< | sed -e 's/^ \+//g' -e 's/\s\+/ /g' -e 's/\<0x0\+\([1-9]\)/0x\1/g' -e 's/ =.*//g' | sort >$@

user/%.o: user/%.c $(HFILES)
	$(CC) -c $(USER_CFLAGS) $< -o $@

user/%.o: user/%.S
	$(AS) $< -o $@

flexatron: $(SIM_OFILES)
	$(CC) $(SIM_CFLAGS) $^ -o $@ $(SIM_LIBS)

sim/%.o: sim/%.c $(HFILES)
	$(CC) -c $(SIM_CFLAGS) $< -o $@

clean:
	rm -f flexatron *.bin *.elf *.map *.sym *.asm *.o **/*.o
