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

# High level variables, these might be set from outside to
# use a custom target directory
DESTDIR?=
PREFIX?=/usr/local
LIBRARY_PATH?=lib
INCLUDE_PATH?=include

# Low level variables.
# ONLY SET THOSE IF YOU KNOW WHAT YOU'RE DOING
LIB_SHORT_PATH?=$(PREFIX)/$(LIBRARY_PATH)
LIB_PATH?=$(DESTDIR)$(LIB_SHORT_PATH)
INC_SHORT_PATH?=$(PREFIX)/$(INCLUDE_PATH)
INC_PATH?=$(DESTDIR)$(INC_SHORT_PATH)
PKGCONFIG_PATH?=$(LIB_PATH)/pkgconfig
PKGCONFIG_NAME?=scion-tcpmw.pc


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
	# Create directories
	install -d $(LIB_PATH)/
	install -d $(INC_PATH)/scion-tcpmw/
	install -d $(PKGCONFIG_PATH)/
	# Install files
	install -m 644 $(STATIC) $(LIB_PATH)/
	install -m 755 $(DYNAMIC) $(LIB_PATH)/
	install -m 644 $(LWIPPORT_DIR)/proj/scion/liblwip.a $(LIB_PATH)
	install -m 755 $(LWIPPORT_DIR)/proj/scion/liblwip.so $(LIB_PATH)
	install -m 644 $(HDRS) $(INC_PATH)/scion-tcpmw/
	# Create pkg-config file
	echo 'libdir=$(LIB_SHORT_PATH)' > $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
	echo 'includedir=$(INC_SHORT_PATH)' >> $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
	cat $(PKGCONFIG_NAME) >> $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)

uninstall:
	rm -f $(LIB_PATH)/$(STATIC)
	rm -f $(LIB_PATH)/$(DYNAMIC)
	rm -f $(LIB_PATH)/liblwip.a
	rm -f $(LIB_PATH)/liblwip.so
	rm -rf $(INC_PATH)/scion
	rm -f $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
