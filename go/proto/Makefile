.PHONY: all capnp

PROTO_DIR := ../../proto
SRCS := $(wildcard $(PROTO_DIR)/*.capnp)
SRCS := $(filter-out $(PROTO_DIR)/go.capnp, $(SRCS))

all: capnp structs.gen.go

capnp:
	set -eu; \
	TMPDIR=$$(mktemp -d -t scion-build-tools.XXXXXXXXXX); \
	bazel build //:build-tools; \
	tar -xf ../../bazel-bin/build-tools.tar -C $$TMPDIR; \
	rm -f *.capnp.go; \
	capnp compile --verbose -o$$TMPDIR/capnpc-go --src-prefix $(PROTO_DIR) $(SRCS); \
	rm -rf $$TMPDIR

structs.gen.go: structs_gen_go.sh
	./structs_gen_go.sh > structs.gen.go
