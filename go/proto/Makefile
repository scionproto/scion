.PHONY: all capnp

PROTO_DIR := ../../proto
SRCS := $(wildcard $(PROTO_DIR)/*.capnp)
SRCS := $(filter-out $(PROTO_DIR)/go.capnp, $(SRCS))

all: capnp structs.gen.go

capnp:
	$(eval $@_TMPDIR := $(shell mktemp -d -t scion-build-tools.XXXXXXXXXX))
	bazel build //:build-tools
	tar -xf ../../bazel-bin/build-tools.tar -C $($@_TMPDIR)
	
	rm -f *.capnp.go
	capnp compile --verbose -o$($@_TMPDIR)/capnpc-go --src-prefix $(PROTO_DIR) $(SRCS)

	rm -rf $($@_TMPDIR)

structs.gen.go: structs_gen_go.sh
	./structs_gen_go.sh > structs.gen.go
