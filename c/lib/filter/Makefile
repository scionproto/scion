.PHONY: all clean install uninstall
LIB_DIR = ..

EXTRA_CFLAGS = -Wall -Werror -fPIC -I$(LIB_DIR)
EXTRA_LDFLAGS = -shared -Wl,-z,defs -Wl,-soname,libfilter.so.0 -lzlog -L$(LIB_DIR)/scion -lscion

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
STATIC = libfilter.a
DYNAMIC = libfilter.so
TARGETS = $(STATIC) $(DYNAMIC)

ifeq ($(PREFIX),)
	PREFIX = /usr/local
endif

all: $(TARGETS)

clean:
	rm -f *.d *.so *.a *.o .installstamp $(TARGETS)

# Compile .c files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(INC) -MMD -c -o $@ $<

$(STATIC): $(OBJS)
	ar rcs $@ $(OBJS)

$(DYNAMIC): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@

install: $(TARGETS)
	echo "Install not implemented yet"

uninstall:
	echo "Uninstall not implemented yet"
