CC = gcc
CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra \
         -Wstrict-prototypes -Wold-style-definition \
         -g -pthread
CFILES = $(wildcard *.c)
OFILES = $(patsubst %.c,%.o,$(CFILES))
HFILES = $(wildcard *.h)

UNICORN_LIBS = $(shell pkg-config --libs unicorn)

.PHONY: clean

flexatron: $(OFILES)
	$(CC) $(CFLAGS) $^ -o $@ $(UNICORN_LIBS)

%.o: %.c $(HFILES)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f flexatron *.o
