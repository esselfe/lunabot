lib_LTLIBRARIES = liblunabot.la

liblunabot_la_SOURCES = liblunabot.c irc.c log.c ../lunabot.h
liblunabot_la_CFLAGS = -std=c17 -Wall -Wno-unused-but-set-variable -I.. $(MICROHTTPD_CFLAGS) \
$(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(CURL_CFLAGS) $(PTHREAD_CFLAGS) -D_DEFAULT_SOURCE
liblunabot_la_LDFLAGS = -module -avoid-version
liblunabot_la_LIBADD = $(MICROHTTPD_LIBS) $(JANSSON_LIBS) $(OPENSSL_LIBS) $(CURL_LIBS) $(PTHREAD_LIBS)

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/liblunabot.la

MAINTAINERCLEANFILES = Makefile.in
