bin_PROGRAMS = lunabot

lunabot_SOURCES = lunabot.c lunabot.h
lunabot_CFLAGS = -std=c17 -Wall -Wno-unused-but-set-variable -Ilib/ $(MICROHTTPD_CFLAGS) $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(PTHREAD_CFLAGS) -D_DEFAULT_SOURCE
lunabot_LDADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(PTHREAD_LIBS)

dist_doc_DATA = $(top_srcdir)/lunabot.conf.json $(top_srcdir)/README.md

MAINTAINERCLEANFILES = Makefile.in
