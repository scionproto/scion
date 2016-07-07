CC=gcc
CFLAGS +=-Wall -g
LIBDIR=../lib/libscion
LWIPDIR=../sub/lwip/src/include
LWIPPORTDIR=../sub/lwip-contrib/ports/unix/
INC += -I./ssp -I../lib/libscion -I$(LWIPDIR) -I$(LWIPDIR)/scion -I$(LWIPDIR)/ipv4 \
	   -I$(LWIPPORTDIR)/include -I$(LWIPPORTDIR)/proj/scion -I../lib
LDFLAGS += -Wl,-Bstatic -L$(LIBDIR) -lscion -Wl,-Bdynamic -lpthread -lzlog \
		   -L$(LWIPPORTDIR)/proj/scion -llwip
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h
SRCS=dispatcher.c ../lib/tcp/middleware.c

HDRS=$(wildcard *.h)

all: dispatcher

dispatcher: dispatcher.c $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(CC) $(CFLAGS) $(INC) $(SRCS) -o $@ $(LDFLAGS)

install:
	cp dispatcher ../bin

clean:
	-rm -f dispatcher
