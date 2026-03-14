CC ?= gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

.PHONY: all clean

all: observer

observer: observer.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f observer
