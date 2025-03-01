
CFLAGS = -std=c17 -Wall -Wno-unused-but-set-variable -D_DEFAULT_SOURCE -O0
LDFLAGS = -lpthread -lmicrohttpd -ljansson -lssl -lcrypto
PROGNAME=lunabot

default: all

all: $(PROGNAME)

$(PROGNAME): lunabot.c
	gcc $(CFLAGS) lunabot.c -o $(PROGNAME) $(LDFLAGS)

clean:
	@rm -v $(PROGNAME) || true

