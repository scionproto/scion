CC=g++
CFLAGS=-Wall -g -std=c++11 -fPIC
LDFLAGS=-shared -lpthread -lscion
LIBDIR=../../lib/libscion
INC=-I$(LIBDIR)
LIBFLAG=-L$(LIBDIR)
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h

HDRS=$(wildcard *.h) $(wildcard ../../lib/libscion/*.h)

SCIOND_DEP=ConnectionManager.cpp Utils.cpp
CLIENT_OBJS=$(SCIOND_DEP:.cpp=._client.o)
SERVER_OBJS=$(SCIOND_DEP:.cpp=._server.o)
COMMON=SCIONSocket.cpp SCIONProtocol.cpp Path.cpp PathState.cpp\
	   OrderedList.cpp Extensions.cpp PathPolicy.cpp SCIONWrapper.cpp
COMMON_OBJS=$(COMMON:.cpp=.o)
SOCKET_OBJS=$(COMMON_OBJS) $(CLIENT_OBJS) $(SERVER_OBJS)
CLIENT_LIB=libclient.so
SERVER_LIB=libserver.so

all: $(CLIENT_LIB) $(SERVER_LIB)

%._client.o: %.cpp $(HDRS)
	# FIXME(aznair): SCIOND_API_SOCKDIR will become ISD_AS.sock in later PR
	$(CC) $(CFLAGS) $(USER_OPTS) $(INC) -c -o $@ $< -DSCIOND_API_SOCKDIR='"/run/shm/sciond/client"'

%._server.o: %.cpp $(HDRS)
	# FIXME(aznair): SCIOND_API_SOCKDIR will become ISD_AS.sock in later PR
	$(CC) $(CFLAGS) $(USER_OPTS) $(INC) -c -o $@ $< -DSCIOND_API_SOCKDIR='"/run/shm/sciond/server"'

%.o: %.cpp $(HDRS)
	$(CC) $(CFLAGS) $(USER_OPTS) $(INC) -c -o $@ $<

$(CLIENT_LIB): $(COMMON_OBJS) $(CLIENT_OBJS) $(HDRS) $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(CC) -o $@ $(COMMON_OBJS) $(CLIENT_OBJS) $(LDFLAGS) $(LIBFLAG)

$(SERVER_LIB): $(COMMON_OBJS) $(SERVER_OBJS) $(HDRS) $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(CC) -o $@ $(COMMON_OBJS) $(SERVER_OBJS) $(LDFLAGS) $(LIBFLAG)

clean:
	-rm -f $(SOCKET_OBJS) $(CLIENT_LIB) $(SERVER_LIB)
