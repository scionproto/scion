.PHONY: all clean install uninstall

#CC = clang
EXTRA_CFLAGS ?= -Wall -Werror -g -O2 -fno-strict-aliasing
EXTRA_LDFLAGS ?= -lpthread -lzlog -Wl,-Bstatic -L../lib/filter -lfilter -L../lib/scion -lscion -Wl,-Bdynamic

LIB_DIR = ../lib
INC = -I$(LIB_DIR)

TARGETS = dispatcher

# High level variables, these might be set from outside to
# use a custom target directory
DESTDIR?=
PREFIX?=..

all: $(TARGETS)

clean:
	rm -f *.d $(TARGETS)

# Compile .c files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
dispatcher: dispatcher.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(INC) -MMD -o $@ $< $(LDFLAGS) $(EXTRA_LDFLAGS)

install: dispatcher
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)/etc/scion
	install -m 755 dispatcher $(DESTDIR)$(PREFIX)/bin
	install -m 644 dispatcher.conf $(DESTDIR)/etc/scion

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/dispatcher
	rm -f $(DESTDIR)/etc/scion/dispatcher.conf
