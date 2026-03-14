ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src

EXTRA_DIST = lunabot.conf.json Makefile.simple README.md LICENSE CLAUDE.md

.PHONY: test test-clean

test: all
	@echo "Running integration tests..."
	@bash $(top_srcdir)/test/run-tests.sh

test-clean:
	docker compose -f $(top_srcdir)/test/docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true

MAINTAINERCLEANFILES = \
	aclocal.m4 \
	ar-lib \
	compile \
	config.guess \
	config.sub \
	configure \
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
