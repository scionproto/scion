CC=gcc
CFLAGS +=-Wall -g
INC += -I./ssp -I../lib/libscion
LDFLAGS += -lpthread -lscion
LIBDIR=../lib/libscion
LIBFLAG=-L$(LIBDIR)
LIBFILE=$(LIBDIR)/libscion.a
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h
SRCS=dispatcher.c

HDRS=$(wildcard *.h)

all: dispatcher

dispatcher: dispatcher.c $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(CC) $(CFLAGS) $(INC) $(SRCS) -o $@ $(LDFLAGS) $(LIBFLAG)

install:
	cp dispatcher ../bin

clean:
	-rm -f dispatcher
