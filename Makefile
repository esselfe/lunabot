
PROGNAME=lunabot

default: all

all: $(PROGNAME)

$(PROGNAME): lunabot.c
	gcc lunabot.c -o lunabot -lpthread -lmicrohttpd -ljansson -lssl -lcrypto

clean:
	@rm -v $(PROGNAME) || true

