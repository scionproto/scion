CC=g++
CFLAGS=-Wall -g -std=c++11 -fPIC
LDFLAGS=-shared -lpthread -lscion
LIBDIR=../../lib/libscion
INC=-I$(LIBDIR)
LIBFLAG=-L$(LIBDIR)
LIBHSRC=$(LIBDIR)/*.c $(LIBDIR)/*.h
LIBSOCK=libsocket.so

HDRS=$(wildcard *.h) $(wildcard ../../lib/libscion/*.h)

SOCKET_SRCS=SCIONSocket.cpp SCIONProtocol.cpp Path.cpp PathState.cpp\
	   		OrderedList.cpp Extensions.cpp PathPolicy.cpp SCIONWrapper.cpp\
			ConnectionManager.cpp Utils.cpp

SOCKET_OBJS=$(SOCKET_SRCS:.cpp=.o)

all: $(LIBSOCK)

%.o: %.cpp $(HDRS)
	$(CC) $(CFLAGS) $(USER_OPTS) $(INC) -c -o $@ $<

$(LIBSOCK): $(SOCKET_OBJS) $(HDRS) $(LIBHSRC)
	$(MAKE) -C $(LIBDIR)
	$(CC) -o $@ $(SOCKET_OBJS) $(LDFLAGS) $(LIBFLAG)

clean:
	rm -f *.so *.o
