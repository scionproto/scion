.PHONY: all clean install uninstall
LIB_DIR = ..

EXTRA_CFLAGS = -Wall -Werror -fPIC -I$(LIB_DIR)
EXTRA_LDFLAGS = -shared -Wl,-z,defs -Wl,-soname,libfilter.so.0 -lzlog -L$(LIB_DIR)/scion -lscion

SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)
STATIC = libfilter.a
DYNAMIC = libfilter.so
TARGETS = $(STATIC) $(DYNAMIC)

ifeq ($(PREFIX),)
	PREFIX = /usr/local
endif

all: $(TARGETS)

clean:
	rm -f *.d *.so *.a *.o $(TARGETS)

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
	install -d $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	install -m 644 $(STATIC) $(DESTDIR)$(PREFIX)/lib/
	install -m 755 $(DYNAMIC) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/scion-filter/
	install -m 644 $(HDRS) $(DESTDIR)$(PREFIX)/include/scion-filter/
	$(eval TMP:= $(shell mktemp -d))
	sed 's@$$PREFIX@'"$(PREFIX)"'@' scion-filter.pc.in > $(TMP)/scion-filter.pc
	install -m 644 $(TMP)/scion-filter.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	rm -rf $(TMP)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(STATIC)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(DYNAMIC)
	rm -rf $(DESTDIR)$(PREFIX)/include/scion-filter/
	rm -f $(DESTDOR)$(PREFIX)/lib/pkgconfig/scion-filter.pc
