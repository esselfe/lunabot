
LDFLAGS = -lpthread -lmicrohttpd -ljansson -lssl -lcrypto
PROGNAME=lunabot

default: all

all: $(PROGNAME)

$(PROGNAME): lunabot.c
	gcc lunabot.c -o $(PROGNAME) $(LDFLAGS)

clean:
	@rm -v $(PROGNAME) || true

