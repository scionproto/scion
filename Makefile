.PHONY: all c clean dispatcher go install lwip

CC=gcc
CFLAGS +=-Wall -g
LIB_DIR=lib/libscion
LIBFILE=$(LIB_DIR)/libscion.a
LIB_H_SRC=$(LIB_DIR)/*.c $(LIB_DIR)/*.h
DISPATCHER_DIR=endhost
DISPATCHER=$(DISPATCHER_DIR)/dispatcher
SOCKET_DIR=endhost/ssp
SOCKET=$(SOCKET_DIR)/libsocket.so
TEST_DIR=$(SOCKET_DIR)/test
LWIP_CONTRIB_DIR=sub/lwip-contrib

all: c lwip dispatcher go

c:
	$(MAKE) -C $(LIB_DIR)
	$(MAKE) -C $(SOCKET_DIR)
	$(MAKE) -C $(TEST_DIR)

go:
	GOBIN=$$PWD/bin go install -v ./go/...

dispatcher:
	$(MAKE) -C $(DISPATCHER_DIR)

lwip:
	$(MAKE) -C $(LWIP_CONTRIB_DIR)

install:
	cp $(DISPATCHER) bin/

clean:
	$(MAKE) clean -C $(LIB_DIR)
	$(MAKE) clean -C $(DISPATCHER_DIR)
	$(MAKE) clean -C $(SOCKET_DIR)
	$(MAKE) clean -C $(TEST_DIR)
	$(MAKE) clean -C $(LWIP_CONTRIB_DIR)
	rm -f bin/dispatcher bin/discovery
