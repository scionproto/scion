.PHONY: all clean install uninstall
LIB_DIR = ..

EXTRA_CFLAGS = -Wall -Werror -fPIC -I$(LIB_DIR) -fno-strict-aliasing -Wno-unused-result
EXTRA_LDFLAGS = -shared -Wl,-z,defs -Wl,-soname,libfilter.so.0 -lzlog -L$(LIB_DIR)/scion -lscion

SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)
STATIC = libfilter.a
DYNAMIC = libfilter.so
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
PKGCONFIG_NAME?=scion-filter.pc

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
	# Create directories
	install -d $(LIB_PATH)/
	install -d $(INC_PATH)/scion-filter/
	install -d $(PKGCONFIG_PATH)/
	# Install files
	install -m 644 $(STATIC) $(LIB_PATH)/
	install -m 755 $(DYNAMIC) $(LIB_PATH)/
	install -m 644 $(HDRS) $(INC_PATH)/scion-filter/
	# Create pkg-config file
	echo 'libdir=$(LIB_SHORT_PATH)' > $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
	echo 'includedir=$(INC_SHORT_PATH)' >> $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
	cat $(PKGCONFIG_NAME) >> $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)

uninstall:
	rm -f $(LIB_PATH)/$(STATIC)
	rm -f $(LIB_PATH)/$(DYNAMIC)
	rm -rf $(INC_PATH)/scion-filter/
	rm -f $(PKGCONFIG_PATH)/$(PKGCONFIG_NAME)
