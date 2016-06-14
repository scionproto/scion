CC=gcc
CFLAGS +=-Wall -g
LIBDIR=../lib/libscion
ZLOGDIR=$(HOME)/.local/lib/zlog/src
LWIPDIR=../sub/lwip/src/include
LWIPPORTDIR=../sub/lwip-contrib/ports/unix/
INC += -I./ssp -I../lib/libscion -I$(ZLOGDIR) -I$(LWIPDIR) -I$(LWIPDIR)/scion -I$(LWIPDIR)/ipv4 \
	   -I$(LWIPPORTDIR)/include -I$(LWIPPORTDIR)/proj/scion -I../lib
LDFLAGS += -Wl,-Bstatic -L$(LIBDIR) -lscion -L$(ZLOGDIR) -lzlog -Wl,-Bdynamic -lpthread \
		   -L$(LWIPPORTDIR)/proj/scion -llwip
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h
SRCS=dispatcher.c tcp/middleware.c

HDRS=$(wildcard *.h)

all: dispatcher

dispatcher: dispatcher.c $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(CC) $(CFLAGS) $(INC) $(SRCS) -o $@ $(LDFLAGS)

install:
	cp dispatcher ../bin

clean:
	-rm -f dispatcher
