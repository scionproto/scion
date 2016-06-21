CC=gcc
CFLAGS +=-Wall -g
LIBDIR=../lib/libscion
FILTERDIR=../lib/libfilter
LWIPDIR=../sub/lwip/src/include
LWIPPORTDIR=../sub/lwip-contrib/ports/unix/
INC += -I./ssp -I../lib/libscion -I$(LWIPDIR) -I$(LWIPDIR)/scion -I$(LWIPDIR)/ipv4 \
	   -I$(LWIPPORTDIR)/include -I$(LWIPPORTDIR)/proj/scion -I../lib -I$(FILTERDIR)
LDFLAGS += -Wl,-Bstatic -L$(LIBDIR) -lscion -L$(FILTERDIR) -Wl,-Bdynamic -lpthread -lzlog \
		   -L$(LWIPPORTDIR)/proj/scion -llwip
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h $(FILTERDIR)/*.c $(FILTERDIR)/*.h
SRCS=dispatcher.c ../lib/tcp/middleware.c $(FILTERDIR)/*.c
HDRS=$(wildcard *.h)

all: dispatcher

dispatcher: dispatcher.c $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(MAKE) -C $(FILTERDIR)
	$(CC) $(CFLAGS) $(INC) $(SRCS) -o $@ $(LDFLAGS)

install:
	cp dispatcher ../bin

clean:
	-rm -f dispatcher
