.PHONY: client server

CC=g++
CFLAGS +=-Wall -g -fPIC
LDFLAGS += -ldl -shared -lpthread -lrt

HDRS=$(wildcard *.h)

SOCKET=SCIONSocket.cpp SCIONProtocol.cpp ConnectionManager.cpp Path.cpp\
	   PathState.cpp OrderedList.cpp Utils.cpp RingBuffer.cpp\
	   SCIONWrapper.cpp

all: client server

client: $(SOCKET) $(HDRS)
	$(CC) $(CFLAGS) -DSCIOND_API_HOST='"127.255.255.254"' $(SOCKET)\
		-o libclient.so $(LDFLAGS)

server: $(SOCKET) $(HDRS)
	$(CC) $(CFLAGS) -DSCIOND_API_HOST='"127.255.255.253"' $(SOCKET)\
		-o libserver.so $(LDFLAGS)

clean:
	-rm -f $(SOCKET_OBJS) libclient.so libserver.so
