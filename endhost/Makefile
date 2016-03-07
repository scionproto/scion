CC=gcc
CFLAGS +=-Wall -g
INC += -I./ssp -I../lib/libscion
LIB=-L../lib/libscion
LDFLAGS += -lpthread -lscion
LIBFILE=../lib/libscion/libscion.a

HDRS=$(wildcard *.h)

all: dispatcher

dispatcher: dispatcher.c
ifeq ($(wildcard $(LIBFILE)),)
	cd ../lib/libscion && $(MAKE)
endif
	$(CC) $(CFLAGS) $(INC) $^ -o $@ $(LDFLAGS) $(LIB)

install:
	cp dispatcher ../bin

clean:
	-rm -f dispatcher
