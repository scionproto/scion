.PHONY: all clean install uninstall

#CC = clang
EXTRA_CFLAGS = -Wall -Werror -fPIC -fno-strict-aliasing -Wno-unused-result
EXTRA_LDFLAGS = -shared -Wl,-z,defs -Wl,-soname,libscion.so.0

SRCS = $(filter-out $(BINARY).c, $(wildcard *.c))
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)
STATIC = libscion.a
DYNAMIC = libscion.so
BINARY = checksum_bench
TARGETS = $(STATIC) $(DYNAMIC) $(BINARY)

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
PKGCONFIG_NAME?=scion.pc

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
	# Create directories
	install -d $(LIB_PATH)/
	install -d $(INC_PATH)/scion/
	install -d $(PKGCONFIG_PATH)/
	# Install files
	install -m 644 $(STATIC) $(LIB_PATH)/
	install -m 755 $(DYNAMIC) $(LIB_PATH)/
	install -m 644 $(HDRS) $(INC_PATH)/scion/
	# Create pkg-config file
	echo 'libdir=$(LIB_SHORT_PATH)' > $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
	echo 'includedir=$(INC_SHORT_PATH)' >> $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
	cat $(PKGCONFIG_NAME) >> $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)

uninstall:
	rm -f $(LIB_PATH)/$(STATIC)
	rm -f $(LIB_PATH)/$(DYNAMIC)
	rm -rf $(INC_PATH)/scion
	rm -f $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
