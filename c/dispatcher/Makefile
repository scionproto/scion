.PHONY: all clean install uninstall

CC = clang
CFLAGS ?= -Wall -Werror -g -O2
LDFLAGS ?= -lpthread -Wl,-Bstatic -lzlog -lfilter -lscion -Wl,-Bdynamic

ifeq ($(D),1)
CFLAGS += -gdwarf-2 -O0 -DZLOG_DEBUG
endif

LIB_DIR = ../lib
INC = -I$(LIB_DIR)

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
