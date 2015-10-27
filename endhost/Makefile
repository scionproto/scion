CC=gcc
CFLAGS +=-Wall -g
INC += -I./sdamp
LDFLAGS += -lpthread -lrt

HDRS=$(wildcard *.h)

all: client_dispatcher server_dispatcher

client_dispatcher: dispatcher.c
	$(CC) $(CFLAGS) $(INC) -DSCION_DISPATCHER_HOST='"127.255.255.254"' $^ -o $@ $(LDFLAGS)

server_dispatcher: dispatcher.c
	$(CC) $(CFLAGS) $(INC) -DSCION_DISPATCHER_HOST='"127.255.255.253"' $^ -o $@ $(LDFLAGS)

dispatcher: dispatcher.c
	$(CC) $(CFLAGS) $(INC) -DSCION_DISPATCHER_HOST='"127.255.255.254"' $^ -o $@ $(LDFLAGS)

clean:
	-rm -f dispatcher client_dispatcher server_dispatcher
