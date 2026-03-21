ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src src/lib

EXTRA_DIST = lunabot.conf.json Makefile.simple README.md LICENSE CLAUDE.md

.PHONY: all-local test test-clean

all-local:
	$(LN_S) -f src/lunabot lunabot

test: all
	@echo "Running integration tests..."
	@bash $(top_srcdir)/test/run-tests.sh

test-clean:
	docker compose -f $(top_srcdir)/test/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true

clean-local:
	rm -f lunabot
	rm -f config.log config.status libtool configure configure~
	rm -f aclocal.m4 ar-lib compile config.guess config.sub depcomp install-sh ltmain.sh missing
	rm -f Makefile.in src/Makefile src/Makefile.in src/lib/Makefile src/lib/Makefile.in
	rm -f m4/libtool.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4
	rm -rf m4
	rm -rf autom4te.cache
	rm -f Makefile

MAINTAINERCLEANFILES = \
	aclocal.m4 \
	ar-lib \
	compile \
	config.guess \
	config.sub \
	configure \
	configure~ \
	depcomp \
	install-sh \
	ltmain.sh \
	missing \
	Makefile.in \
	m4/libtool.m4 \
	m4/ltoptions.m4 \
	m4/ltsugar.m4 \
	m4/ltversion.m4 \
	m4/lt~obsolete.m4
