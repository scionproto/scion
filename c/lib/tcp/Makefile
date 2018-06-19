.PHONY: all clean install uninstall

#CC = clang
EXTRA_CFLAGS ?= -Wall -Werror -g -fPIC -fno-strict-aliasing
EXTRA_LDFLAGS ?= -shared -Wl,-z,defs -Wl,-soname,libtcpmw.so.0 -lpthread -lzlog -L ../scion -lscion -L ../../../sub/lwip-contrib/ports/unix/proj/scion -llwip

LIB_DIR = ..
LWIP_DIR = ../../../sub/lwip/src/include
LWIPPORT_DIR = ../../../sub/lwip-contrib/ports/unix
INC = -I$(LIB_DIR) -I$(LWIP_DIR) -I$(LWIP_DIR)/scion -I$(LWIP_DIR)/ipv4
INC += -I$(LWIPPORT_DIR)/include -I$(LWIPPORT_DIR)/proj/scion

SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)
STATIC = libtcpmw.a
DYNAMIC = libtcpmw.so
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
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(EXTRA_LDFLAGS)

install: $(TARGETS)
	install -d $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	install -m 644 $(STATIC) $(DESTDIR)$(PREFIX)/lib/
	install -m 755 $(DYNAMIC) $(DESTDIR)$(PREFIX)/lib/
	install -m 644 $(LWIPPORT_DIR)/proj/scion/liblwip.a $(DESTDIR)$(PREFIX)/lib/
	install -m 755 $(LWIPPORT_DIR)/proj/scion/liblwip.so $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/scion-tcpmw/
	install -m 644 $(HDRS) $(DESTDIR)$(PREFIX)/include/scion-tcpmw/
	$(eval TMP:= $(shell mktemp -d))
	sed 's@$$PREFIX@'"$(PREFIX)"'@' scion-tcpmw.pc.in > $(TMP)/scion-tcpmw.pc
	install -m 644 $(TMP)/scion-tcpmw.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	rm -rf $(TMP)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(STATIC)
	rm -f $(DESTDIR)$(PREFIX)/lib/$(DYNAMIC)
	rm -f $(DESTDIR)$(PREFIX)/lib/liblwip.a
	rm -f $(DESTDIR)$(PREFIX)/lib/liblwip.so
	rm -rf $(DESTDIR)$(PREFIX)/include/scion-tcpmw/
	rm -f $(DESTDIR)$(PREFIX)/lib/pkgconfig/scion-tcpmw.pc
