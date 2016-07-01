CC=gcc
CFLAGS +=-Wall -g -fPIC

LIBDIR=../libscion
INC += -I$(LIBDIR)
LDFLAGS += -shared -L$(LIBDIR) -lscion -lzlog

HDRS=$(wildcard *.h)
FILES=$(wildcard *.c)
OBJS=$(FILES:.c=.o)
LIB=libfilter.a

all: $(LIB)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $< $(LDFLAGS)

$(LIB): $(OBJS)
	$(MAKE) -C $(LIBDIR)
	ar rcs $@ $(OBJS)

clean:
	-rm -f *.o $(LIB)