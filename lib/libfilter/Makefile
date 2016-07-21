.PHONY: all clean install uninstall

CC = clang
CFLAGS ?= -Wall -Werror -g -fPIC
LDFLAGS ?= -shared -Wl,-z,defs -lscion -lzlog

LIB_DIR = ..
INC = -I$(LIB_DIR)

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
STATIC = libfilter.a
DYNAMIC = libfilter.so
TARGETS = $(STATIC) $(DYNAMIC)
PREFIX ?= /usr/local

all: $(TARGETS)

clean:
	rm -f *.d *.so *.a *.o .installstamp $(TARGETS)

# Compile .c files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
%.o: %.c
	$(CC) $(CFLAGS) $(INC) -MMD -c -o $@ $<

$(STATIC): $(OBJS)
	ar rcs $@ $(OBJS)

$(DYNAMIC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

install: .installstamp

.installstamp: $(TARGETS)
	sudo cp $(TARGETS) $(PREFIX)/lib/
	sudo ldconfig
	touch .installstamp

uninstall:
	$(foreach var,$(TARGETS),sudo rm -f $(PREFIX)/lib/$(var);)
	sudo ldconfig
	rm -f .installstamp
