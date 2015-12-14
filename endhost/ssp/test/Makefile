CC = gcc
PP = g++
CFLAGS += -Wall -g
LIB = -L..
INC = -I..
HDRS=$(wildcard ../*.h)
BINARIES = client server hash_client hash_server web_client web_server
WRAPPED = wrapper_client wrapper_server

all: $(BINARIES)

client: client.cpp $(HDRS)
	$(PP) -o client $(INC) $(LIB) $(CFLAGS) client.cpp -lclient

server: server.cpp $(HDRS)
	$(PP) -o server $(INC) $(LIB) $(CFLAGS) server.cpp -lserver

hash_client: hash_client.cpp $(HDRS)
	$(PP) -o hash_client $(INC) $(LIB) $(CFLAGS) hash_client.cpp SHA1.cpp -lclient

hash_server: hash_server.cpp $(HDRS)
	$(PP) -o hash_server $(INC) $(LIB) $(CFLAGS) hash_server.cpp SHA1.cpp -lserver

web_client: web_client.cpp $(HDRS)
	$(PP) -o web_client $(INC) $(LIB) $(CFLAGS) web_client.cpp -lclient -lcurl

web_server: web_server.cpp $(HDRS)
	$(PP) -o web_server $(INC) $(LIB) $(CFLAGS) web_server.cpp -lserver -lcurl

wrapper_client: wrapper_client.c $(HDRS)
	$(CC) $(INC) $(CFLAGS) -c wrapper_client.c
	$(PP) $(LIB) -o wrapper_client wrapper_client.o -lclient

wrapper_server: wrapper_server.c $(HDRS)
	$(CC) $(INC) $(CFLAGS) -c wrapper_server.c
	$(PP) $(LIB) -o wrapper_server wrapper_server.o -lserver

clean:
	rm -rf $(BINARIES) $(WRAPPED) *.o
