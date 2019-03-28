CC = gcc
LD = ld
CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra \
         -Wstrict-prototypes -Wold-style-definition
HFILES = $(wildcard **/*.h)

USER_CFLAGS = $(CFLAGS) -fno-builtin
USER_CFILES = $(wildcard user/*.c)
USER_OFILES = $(patsubst %.c,%.o,$(USER_CFILES))

SIM_CFLAGS = $(CFLAGS) -g -pthread
SIM_LIBS = $(shell pkg-config --libs unicorn)
SIM_CFILES = $(wildcard sim/*.c)
SIM_OFILES = $(patsubst %.c,%.o,$(SIM_CFILES))

.PHONY: all student clean

all: student flexatron

student: student.bin student.sym

student.bin student.map: student.ld $(USER_OFILES)
	$(LD) -T student.ld -Map=student.map --oformat=binary -static -o student.bin $(USER_OFILES)

# Produce a simpler symbol table file
student.sym: student.map
	grep -E '(^\.(text|bss|data))|(^[[:space:]]+0x[[:alnum:]]+[[:space:]]+[a-zA-Z_]+$$)' $< | sed -e 's/^ \+//g' -e 's/\s\+/ /g' -e 's/\<0x0\+/0x/g' | sort >$@

user/%.o: user/%.c $(HFILES)
	$(CC) -c $(USER_CFLAGS) $< -o $@

flexatron: $(SIM_OFILES)
	$(CC) $(SIM_CFLAGS) $^ -o $@ $(SIM_LIBS)

sim/%.o: sim/%.c $(HFILES)
	$(CC) -c $(SIM_CFLAGS) $< -o $@

clean:
	rm -f flexatron *.bin *.map *.sym *.o **/*.o
