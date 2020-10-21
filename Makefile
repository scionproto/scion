.PHONY: all bazel clean gazelle gogen licenses mocks protobuf setcap
.NOTPARALLEL:

GAZELLE_MODE?=fix
GAZELLE_DIRS=./go ./acceptance

build: bazel

# all: performs the code-generation steps and then builds; the generated code
# is git controlled, and therefore this is only necessary when changing the
# sources for the code generation.
# Note: built in correct order, because .NOTPARALLEL.
all: go_deps.bzl gogen protobuf mocks gazelle licenses build

clean:
	bazel clean
	rm -f bin/*

bazel:
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

go_deps.bzl: go.mod
	@tools/godeps.sh

gogen:
	$(MAKE) -C go/proto

protobuf:
	bazel build //go/pkg/proto/control_plane:proto_srcs \
		//go/pkg/proto/crypto:proto_srcs \
		//go/pkg/proto/discovery:proto_srcs \
		//go/pkg/proto/daemon:proto_srcs \
		//go/pkg/proto/gateway:proto_srcs

	rm -f go/pkg/proto/*/*.pb.go

	tar -kxf bazel-bin/go/pkg/proto/control_plane/proto_srcs.tar -C go/pkg/proto/control_plane
	tar -kxf bazel-bin/go/pkg/proto/crypto/proto_srcs.tar -C go/pkg/proto/crypto
	tar -kxf bazel-bin/go/pkg/proto/discovery/proto_srcs.tar -C go/pkg/proto/discovery
	tar -kxf bazel-bin/go/pkg/proto/daemon/proto_srcs.tar -C go/pkg/proto/daemon
	tar -kxf bazel-bin/go/pkg/proto/gateway/proto_srcs.tar -C go/pkg/proto/gateway

	chmod 0644 go/pkg/proto/*/*.pb.go

mocks:
	./tools/gomocks
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build $(GAZELLE_DIRS)

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build $(GAZELLE_DIRS)

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep ./bin/braccept

licenses:
	tools/licenses.sh
