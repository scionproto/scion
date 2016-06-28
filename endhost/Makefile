CC=gcc
CFLAGS +=-Wall -g
LIBDIR=../lib/libscion
INC += -I./ssp -I../lib/libscion
LDFLAGS += -Wl,-Bstatic -L$(LIBDIR) -lscion -Wl,-Bdynamic -lpthread -lzlog
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h
SRCS=dispatcher.c

HDRS=$(wildcard *.h)

all: dispatcher

dispatcher: dispatcher.c $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(CC) $(CFLAGS) $(INC) $(SRCS) -o $@ $(LDFLAGS)

install:
	cp dispatcher ../bin

clean:
	-rm -f dispatcher
