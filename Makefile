-include local.mk

CC ?= cc
PERL ?= perl
CFLAGS ?= -Wall -g -std=gnu99
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LDFLAGS = $(shell pkg-config --libs glib-2.0)

# These are the common sources used by the server and the tests
LIB_SOURCES = request.c hdrlist.c mimetypes.c
LIB_OBJS = $(patsubst %.c, %.o, $(LIB_SOURCES))

# All the sources used in the HTTP server
HTTPD_SOURCES = httpd.c $(LIB_SOURCES)
HTTPD_OBJS = $(patsubst %.c, %.o, $(HTTPD_SOURCES))

# All the sources used in the forking HTTP server
FORK_HTTPD_SOURCES = forking-httpd.c $(LIB_SOURCES)
FORK_HTTPD_OBJS = $(patsubst %.c, %.o, $(FORK_HTTPD_SOURCES))

# These are the tests for internal C components
TEST_SOURCES = $(wildcard test_*.c)
TEST_OBJS = $(patsubst %.c, %.o, $(TEST_SOURCES))

SUBMIT_FILES = $(wildcard *.c *.h *.ch *.sh *.txt) Makefile
HANDOUT_FILES = $(LIB_SOURCES) httpd.c
HANDOUT_FILES += $(TEST_SOURCES) scan-tests.pl run-tests.c
HANDOUT_FILES += $(patsubst %.c, %.h, $(LIB_SOURCES))
HANDOUT_FILES += httpdefs.h debug.h mime_type_table.ch Makefile listen.sh

.PHONY: all clean check test-lib test-httpd dist

all:

clean:
	rm -f httpd run-tests
	rm -f $(LIB_OBJS)
	rm -f run-tests.o $(TEST_OBJS)

check: test-lib

test-lib: run-tests
	./run-tests

ifeq ($(shell test -f httpd.c && echo yes || echo no), yes)
all: httpd

httpd: $(HTTPD_OBJS)
	$(CC) -o $@ $(HTTPD_OBJS) $(LDFLAGS) $(GLIB_LDFLAGS)

test-httpd: httpd
	prove -f -I t/lib

check: test-httpd
endif

ifeq ($(shell test -f forking-httpd.c && echo yes || echo no), yes)
all: forking-httpd

forking-httpd: $(FORK_HTTPD_OBJS)
	$(CC) -o $@ $(FORK_HTTPD_OBJS) $(LDFLAGS) $(GLIB_LDFLAGS)
endif

a6-submit.tgz: $(SUBMIT_FILES)
	mkdir -p assignment6-submission
	cp $(SUBMIT_FILES) assignment6-submission
	tar cvzf $@ assignment6-submission

a6-handout.tgz: $(HANDOUT_FILES) assignment6.pdf
	pax -w -s '@^@assignment6/@' -z -f $@ assignment6.pdf $(HANDOUT_FILES) test-site t

dist:
	pax -w -s '@^@eduhttpd/@' -z -f httpd.tgz Makefile *.c *.h *.ch listen.sh t

run-tests: run-tests.o $(TEST_OBJS) $(LIB_OBJS)
	$(CC) -o $@ run-tests.o $(TEST_OBJS) $(LIB_OBJS) $(LDFLAGS) $(GLIB_LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GLIB_CFLAGS) -c -o $@ $<

test_%.ch: test_%.c
	$(PERL) scan-tests.pl $< >.$@.tmp && mv .$@.tmp $@

ifdef MIME_TYPES
mime_type_table.ch: parse-mime.pl $(MIME_TYPES)
	$(PERL) parse-mime.pl $(MIME_TYPES) >$@.tmp && mv $@.tmp $@
endif

deps.mk: $(LIB_SOURCES) $(TEST_SOURCES)
	$(CC) $(CPPFLAGS) $(GLIB_CFLAGS) -MM -MG $(LIB_SOURCES) $(TEST_SOURCES) >$@ || (rm -f $@; exit 2)

tags: $(wildcard *.c *.h)
	ctags *.c *.h

%.pdf: ../%.md
	pandoc -t latex --latex-engine=xelatex -o $@ $<

-include deps.mk
