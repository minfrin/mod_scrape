
AM_CFLAGS = ${apr_CFLAGS} ${apu_CFLAGS}
AM_LDFLAGS = ${apr_LDFLAGS} ${apu_LDFLAGS}

EXTRA_DIST = mod_scrape.c mod_scrape.spec debian/changelog debian/compat debian/control debian/copyright debian/docs debian/mod-scrape.substvars debian/mod-scrape.dirs debian/rules debian/source/format README.md

all-local:
	$(APXS) -c $(DEF_LDLIBS) -Wc,"$(CFLAGS)" -Wc,"$(AM_CFLAGS)" -Wl,"$(LDFLAGS)" -Wl,"$(AM_LDFLAGS)" $(LIBS) @srcdir@/mod_scrape.c

install-exec-local: 
	mkdir -p $(DESTDIR)`$(APXS) -q LIBEXECDIR`
	$(APXS) -S LIBEXECDIR=$(DESTDIR)`$(APXS) -q LIBEXECDIR` -c -i $(DEF_LDLIBS) -Wc,"$(CFLAGS)" -Wc,"$(AM_CFLAGS)" -Wl,"$(LDFLAGS)" -Wl,"$(AM_LDFLAGS)" $(LIBS) @srcdir@/mod_scrape.c

