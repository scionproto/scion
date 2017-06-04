.PHONY: wrapper

CC = clang
CFLAGS ?= -g
CXX = clang++
CXXFLAGS ?= $(CFLAGS) -std=c++11
LIB = -L..
INC = -I.. -I../../../lib/scion
HDRS=$(wildcard ../*.h)
BINARIES = client server hash_client hash_server web_client web_server wrapper_client wrapper_server

all: $(BINARIES)

client: client.cpp $(HDRS)
	$(CXX) -o client $(INC) $(LIB) $(CXXFLAGS) client.cpp -lssocket -Wl,-rpath,..

server: server.cpp $(HDRS)
	$(CXX) -o server $(INC) $(LIB) $(CXXFLAGS) server.cpp -lssocket -Wl,-rpath,..

hash_client: hash_client.cpp $(HDRS)
	$(CXX) -o hash_client $(INC) $(LIB) $(CXXFLAGS) hash_client.cpp SHA1.cpp -lssocket -Wl,-rpath,..

hash_server: hash_server.cpp $(HDRS)
	$(CXX) -o hash_server $(INC) $(LIB) $(CXXFLAGS) hash_server.cpp SHA1.cpp -lssocket -Wl,-rpath,..

web_client: web_client.cpp $(HDRS)
	$(CXX) -o web_client $(INC) $(LIB) $(CXXFLAGS) web_client.cpp -lssocket -lcurl -Wl,-rpath,..

web_server: web_server.cpp $(HDRS)
	$(CXX) -o web_server $(INC) $(LIB) $(CXXFLAGS) web_server.cpp -lssocket -lcurl -Wl,-rpath,..

wrapper: wrapper_client wrapper_server

wrapper_client: wrapper_client.c $(HDRS)
	$(CC) $(INC) $(CFLAGS) -c wrapper_client.c
	$(CXX) $(LIB) -o wrapper_client wrapper_client.o -lssocket -Wl,-rpath,..

wrapper_server: wrapper_server.c $(HDRS)
	$(CC) $(INC) $(CFLAGS) -c wrapper_server.c
	$(CXX) $(LIB) -o wrapper_server wrapper_server.o -lssocket -Wl,-rpath,..

clean:
	rm -f $(BINARIES) $(WRAPPED) *.o
