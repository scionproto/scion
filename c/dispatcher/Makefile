.PHONY: all clean install uninstall

CC = clang
CFLAGS ?= -Wall -Werror -g -O2
LDFLAGS ?= -lpthread -Wl,-Bstatic -lzlog -ltcpmw -llwip -lfilter -lscion -Wl,-Bdynamic

LIB_DIR = ../lib
LWIPDIR = ../../sub/lwip/src/include
LWIPPORTDIR = ../../sub/lwip-contrib/ports/unix
INC = -I$(LIB_DIR) -I$(LWIPDIR) -I$(LWIPDIR)/scion -I$(LWIPDIR)/ipv4
INC += -I$(LWIPPORTDIR)/include -I$(LWIPPORTDIR)/proj/scion

TARGETS = dispatcher
INSTALL = ../../bin/dispatcher
PREFIX = ..
all: $(TARGETS)

clean:
	rm -f *.d $(TARGETS)

# Compile .c files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
dispatcher: dispatcher.c
	$(CC) $(CFLAGS) $(INC) -MMD -o $@ $< $(LDFLAGS)

install: $(INSTALL)

$(INSTALL): dispatcher
	cp -f dispatcher $@

uninstall:
	rm -f $(INSTALL)
