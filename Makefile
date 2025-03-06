
CFLAGS = -std=c17 -Wall -Wno-unused-but-set-variable -D_DEFAULT_SOURCE -O0
LDFLAGS = -lpthread -lmicrohttpd -ljansson -lssl -lcrypto
OBJDIR = obj
OBJS = $(OBJDIR)/lunabot.o
PROGNAME = lunabot
LIBNAME = liblunabot.so

.PHONY: default all prepare clean

default: all

all: prepare $(LIBNAME) $(PROGNAME)
	@ls -l --color=auto $(PROGNAME) || true

prepare:
	@[ -d "$(OBJDIR)" ] || mkdir -v "$(OBJDIR)"

$(LIBNAME): src/liblunabot.c
	gcc -shared -fPIC $(CFLAGS) src/liblunabot.c -o $(LIBNAME) $(LDFLAGS)

$(OBJDIR)/lunabot.o: src/lunabot.c
	gcc -c $(CFLAGS) src/lunabot.c -o $(OBJDIR)/lunabot.o

$(PROGNAME): $(OBJS)
	gcc $(OBJS) -o $(PROGNAME) $(LDFLAGS)

clean:
	@rm -rfv $(OBJDIR) $(PROGNAME) || true

