.PHONY: all clean install uninstall

#CC = clang
EXTRA_CFLAGS = -Wall -Werror -fPIC
EXTRA_LDFLAGS = -shared -Wl,-z,defs -Wl,-soname,libscion.so.0

SRCS = $(filter-out $(BINARY).c, $(wildcard *.c))
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)
STATIC = libscion.a
DYNAMIC = libscion.so
BINARY = checksum_bench
TARGETS = $(STATIC) $(DYNAMIC) $(BINARY)

ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

all: $(TARGETS)

clean:
	rm -f *.d *.so *.a *.o $(TARGETS)

# Compile .c files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -MMD -c -o $@ $<

$(STATIC): $(OBJS)
	ar rcs $@ $(OBJS)

$(DYNAMIC): $(OBJS)
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS)

$(BINARY): $(BINARY).c $(DYNAMIC)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -MMD -o $@ $< -L. -lscion

install: $(TARGETS)
	install -d $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	install -m 644 $(STATIC) $(DESTDIR)$(PREFIX)/lib/
	install -m 755 $(DYNAMIC) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/scion/
	install -m 644 $(HDRS) $(DESTDIR)$(PREFIX)/include/scion/
	$(eval TMP := $(shell mktemp -d))
	sed 's@$$PREFIX@'"$(PREFIX)"'@' scion.pc.in > $(TMP)/scion.pc
	install -m 644 $(TMP)/scion.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	rm -rf $(TMP)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(STATIC)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(DYNAMIC)
	rm -rf $(DESTDIR)$(PREFIX)/include/scion
	rm -f $(DESTDIR)$(PREFIX)/lib/pkgconfig/scion.pc
