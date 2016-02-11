CC=gcc
CFLAGS=-Wall -g -fPIC
LDFLAGS=-shared

HDRS=$(wildcard *.h)
FILES=$(wildcard *.c)
OBJS=$(FILES:.c=.o)
LIB=libscion.a

all: $(LIB)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	ar rcs $@ $(OBJS)

clean:
	-rm -f $(OBJS) $(LIB)
