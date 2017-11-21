.PHONY: all stale clean

PROTO_DIR = ../../proto
SRCS := $(wildcard $(PROTO_DIR)/*.capnp)
SRCS := $(filter-out $(PROTO_DIR)/go.capnp, $(SRCS))
SRCS := $(filter-out $(PROTO_DIR)/*.gen, $(SRCS))
OUTS = $(patsubst $(PROTO_DIR)/%, %.go, $(SRCS))
STALE := $(filter-out $(OUTS),$(wildcard *.capnp.go))

all: stale $(OUTS) structs.gen.go

stale:
ifdef STALE
	@rm -v $(STALE)
endif

%.go: $(PROTO_DIR)/%
	capnp compile -I../vendor/zombiezen.com/go/capnproto2/std -ogo --src-prefix=$(PROTO_DIR) $<

%.gen.go: gen.go
	go run gen.go

clean:
	rm -f *.capnp.go *.gen.go

uninstall:
