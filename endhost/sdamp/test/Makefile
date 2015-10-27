CC = g++
CFLAGS += -Wall -g
LIBDIR = ..
INC = -I.. -I../.. -I/usr/include/python3.4
HDRS=$(wildcard *.h)
PYTHON_LD = /usr/lib/python3.4/config-3.4m-x86_64-linux-gnu

all: client server

client: client.cpp ../$(HDRS)
	$(CC) -o client $(INC) -L$(LIBDIR) -L$(PYTHON_LD) $(CFLAGS) client.cpp SHA1.cpp -lclient -lpython3.4 -lcurl

server: server.cpp ../$(HDRS)
	$(CC) -o server $(INC) -L$(LIBDIR) -L$(PYTHON_LD) $(CFLAGS) server.cpp SHA1.cpp -lserver -lpython3.4 -lcurl

clean:
	rm -rf client server
