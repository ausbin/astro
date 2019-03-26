CC = gcc
CFLAGS = -std=c99 -pedantic -Wall -Werror -Wextra -g \
         -Wstrict-prototypes -Wold-style-definition
CFILES = $(wildcard *.c)
OFILES = $(patsubst %.c,%.o,$(CFILES))
HFILES = $(wildcard *.h)

flexatron: $(OFILES)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c $(HFILES)
	$(CC) -c $(CFLAGS) $< -o $@
