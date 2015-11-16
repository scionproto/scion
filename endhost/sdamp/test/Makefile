CC = g++
CFLAGS += -Wall -g
LIBDIR = ..
INC = -I..
HDRS=$(wildcard ../*.h)
BINARIES = client server hash_client hash_server web_client web_server

all: $(BINARIES)

client: client.cpp $(HDRS)
	$(CC) -o client $(INC) -L$(LIBDIR) $(CFLAGS) client.cpp -lclient

server: server.cpp $(HDRS)
	$(CC) -o server $(INC) -L$(LIBDIR) $(CFLAGS) server.cpp -lserver

hash_client: hash_client.cpp $(HDRS)
	$(CC) -o hash_client $(INC) -L$(LIBDIR) $(CFLAGS) hash_client.cpp SHA1.cpp -lclient

hash_server: hash_server.cpp $(HDRS)
	$(CC) -o hash_server $(INC) -L$(LIBDIR) $(CFLAGS) hash_server.cpp SHA1.cpp -lserver

web_client: web_client.cpp $(HDRS)
	$(CC) -o web_client $(INC) -L$(LIBDIR) $(CFLAGS) web_client.cpp -lclient -lcurl

web_server: web_server.cpp $(HDRS)
	$(CC) -o web_server $(INC) -L$(LIBDIR) $(CFLAGS) web_server.cpp -lserver -lcurl

clean:
	rm -rf $(BINARIES)
