CC = gcc
CFLAGS = -g -pedantic -Wall -Werror -Wextra \
         -Wno-parentheses -Wstrict-prototypes -Wold-style-definition \
		 -pthread -std=gnu99 -fPIC -Iinclude
HFILES = $(wildcard **/*.h)
# TODO: include these as submodules for easier building
LIBS = -l:libunicorn.a -l:libdw.a -l:libelf.a -l:libebl.a
CFILES = $(wildcard src/*.c)
OFILES = $(patsubst %.c,%.o,$(CFILES))

.PHONY: all clean

all: libastro.so

libastro.so: $(OFILES)
	$(CC) -shared $(CFLAGS) $^ -o $@ $(LIBS)

src/%.o: src/%.c $(HFILES)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.so *.o src/*.o
