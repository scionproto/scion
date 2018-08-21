.PHONY: all clean install uninstall

CC = clang
CFLAGS ?= -Wall -Werror -g -fPIC -O2
LDFLAGS ?= -shared -Wl,-z,defs

ifeq ($(D),1)
CFLAGS += -gdwarf-2 -O0
endif

SRCS = $(filter-out $(BINARY).c, $(wildcard *.c))
OBJS = $(SRCS:.c=.o)
STATIC = libscion.a
DYNAMIC = libscion.so
BINARY = checksum_bench
TARGETS = $(STATIC) $(DYNAMIC) $(BINARY)
PREFIX ?= /usr/local

all: $(TARGETS)

clean:
	rm -f *.d *.so *.a *.o .installstamp $(TARGETS)

# Compile .c files, while also automatically generating dependencies so they
# can be recompiled if any of the included header files changed.
-include *.d
%.o: %.c
	$(CC) $(CFLAGS) -MMD -c -o $@ $<

$(STATIC): $(OBJS)
	ar rcs $@ $(OBJS)

$(DYNAMIC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

checksum_bench: checksum_bench.c $(DYNAMIC)
	$(CC) $(CFLAGS) -MMD -o $@ $< -L. -lscion

install: .installstamp

.installstamp: $(TARGETS)
	@sudo -vp "c/lib/scion:install [sudo] password for %p: "
	sudo cp $(TARGETS) $(PREFIX)/lib/
	sudo ldconfig
	touch .installstamp

uninstall:
	@sudo -vp "c/lib/scion:uninstall [sudo] password for %p: "
	$(foreach var,$(TARGETS),sudo rm -f $(PREFIX)/lib/$(var);)
	sudo ldconfig
	rm -f .installstamp
