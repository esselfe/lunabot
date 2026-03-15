lib_LTLIBRARIES = liblunabot.la

liblunabot_la_SOURCES = liblunabot.c lunabot.h
liblunabot_la_CFLAGS = $(MICROHTTPD_CFLAGS) $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(CURL_CFLAGS) $(PTHREAD_CFLAGS) -D_DEFAULT_SOURCE
liblunabot_la_LDFLAGS = -module -avoid-version
liblunabot_la_LIBADD = $(MICROHTTPD_LIBS) $(JANSSON_LIBS) $(OPENSSL_LIBS) $(CURL_LIBS) $(PTHREAD_LIBS)

bin_PROGRAMS = lunabot

lunabot_SOURCES = lunabot.c lunabot.h
lunabot_CFLAGS = $(MICROHTTPD_CFLAGS) $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(PTHREAD_CFLAGS) -D_DEFAULT_SOURCE
lunabot_LDADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(PTHREAD_LIBS)

dist_doc_DATA = $(top_srcdir)/lunabot.conf.json $(top_srcdir)/README.md

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/liblunabot.la

MAINTAINERCLEANFILES = Makefile.in
