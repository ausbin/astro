CC = gcc
# Need to use -isystem here to ignore warnings in elfutils headers
CFLAGS = -g -pedantic -Wall -Werror -Wextra \
         -Wno-parentheses -Wstrict-prototypes -Wold-style-definition \
		 -pthread -std=gnu99 -fPIC -Iinclude \
		 -isystem submods/install-path/include
HFILES = $(wildcard include/*.h src/*.h)
LIBS = -Llib -lunicorn -ldw -lelf
CFILES = $(wildcard src/*.c)
OFILES = $(patsubst %.c,%.o,$(CFILES))

.PHONY: all clean

all: lib/libastro.so

lib/libastro.so: $(OFILES)
	$(CC) -shared $(CFLAGS) $^ -o $@ $(LIBS)

src/%.o: src/%.c $(HFILES)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f lib/libastro.so *.o src/*.o
