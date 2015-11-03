CC = g++
CFLAGS += -Wall -g
LIBDIR = ..
INC = -I.. -I../.. -I/usr/include/python3.4
HDRS=$(wildcard *.h)
PYTHON_LD = /usr/lib/python3.4/config-3.4m-x86_64-linux-gnu
BINARIES = client server hash_client hash_server web_client web_server

all: $(BINARIES)

client: client.cpp ../$(HDRS)
	$(CC) -o client $(INC) -L$(LIBDIR) -L$(PYTHON_LD) $(CFLAGS) client.cpp -lclient

server: server.cpp ../$(HDRS)
	$(CC) -o server $(INC) -L$(LIBDIR) -L$(PYTHON_LD) $(CFLAGS) server.cpp -lserver

hash_client: hash_client.cpp ../$(HDRS)
	$(CC) -o hash_client $(INC) -L$(LIBDIR) $(CFLAGS) hash_client.cpp SHA1.cpp -lclient -lncurses

hash_server: hash_server.cpp ../$(HDRS)
	$(CC) -o hash_server $(INC) -L$(LIBDIR) $(CFLAGS) hash_server.cpp SHA1.cpp -lserver -lncurses

web_client: web_client.cpp ../$(HDRS)
	$(CC) -o web_client $(INC) -L$(LIBDIR) $(CFLAGS) web_client.cpp -lclient -lncurses -lcurl

web_server: web_client.cpp ../$(HDRS)
	$(CC) -o web_server $(INC) -L$(LIBDIR) $(CFLAGS) web_server.cpp -lserver -lncurses -lcurl

clean:
	rm -rf $(BINARIES)
