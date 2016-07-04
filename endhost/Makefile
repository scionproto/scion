CC=gcc
CFLAGS +=-Wall -g
LIBDIR=../lib/libscion
FILTERDIR=../lib/libfilter
INC += -I./ssp -I$(LIBDIR) -I$(FILTERDIR)
LDFLAGS += -Wl,-Bstatic -L$(LIBDIR) -lscion -L$(FILTERDIR) -Wl,-Bdynamic -lpthread -lzlog
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h $(FILTERDIR)/*.c $(FILTERDIR)/*.h
SRCS=dispatcher.c $(FILTERDIR)/*.c

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
