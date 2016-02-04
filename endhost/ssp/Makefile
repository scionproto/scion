CC=g++
CFLAGS=-Wall -g -fPIC -std=c++11
LDFLAGS=-ldl -shared -lpthread -lrt

HDRS=$(wildcard *.h)

SCIOND_DEP=ConnectionManager.cpp Utils.cpp
CLIENT_OBJS=$(SCIOND_DEP:.cpp=._client.o)
SERVER_OBJS=$(SCIOND_DEP:.cpp=._server.o)
COMMON=SCIONSocket.cpp SCIONProtocol.cpp Path.cpp PathState.cpp\
	   OrderedList.cpp SCIONWrapper.cpp Extensions.cpp
COMMON_OBJS=$(COMMON:.cpp=.o)
SOCKET_OBJS=$(COMMON_OBJS) $(CLIENT_OBJS) $(SERVER_OBJS)
CLIENT_LIB=libclient.so
SERVER_LIB=libserver.so

all: $(CLIENT_LIB) $(SERVER_LIB)

%._client.o: %.cpp $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $< -DSCIOND_API_HOST='"127.255.255.254"'

%._server.o: %.cpp $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $< -DSCIOND_API_HOST='"127.255.255.253"'

%.o: %.cpp $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(CLIENT_LIB): $(COMMON_OBJS) $(CLIENT_OBJS) $(HDRS)
	$(CC) $(CFLAGS) $(COMMON_OBJS) $(CLIENT_OBJS) -o $@ $(LDFLAGS)

$(SERVER_LIB): $(COMMON_OBJS) $(SERVER_OBJS) $(HDRS)
	$(CC) $(CFLAGS) $(COMMON_OBJS) $(SERVER_OBJS) -o $@ $(LDFLAGS)

clean:
	-rm -f $(SOCKET_OBJS) $(CLIENT_LIB) $(SERVER_LIB)
