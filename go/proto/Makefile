.PHONY: all clean

PROTO_DIR = ../../proto
SRCS := $(wildcard $(PROTO_DIR)/*.capnp)
SRCS := $(filter-out $(PROTO_DIR)/go.capnp, $(SRCS))
OUTS = $(patsubst $(PROTO_DIR)/%, %.go, $(SRCS))

all: $(OUTS)

%.go: $(PROTO_DIR)/%
	capnp compile -I$(GOPATH)/src/zombiezen.com/go/capnproto2/std -ogo --src-prefix=$(PROTO_DIR) $<

clean:
	rm -f *.capnp.go

uninstall:
