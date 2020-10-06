.PHONY: all clean protobuf protobuf_clean godeps gogen mocks bazel gazelle setcap licenses

GAZELLE_MODE?=fix
GAZELLE_DIRS=./go ./acceptance

all: bazel

clean:
	bazel clean
	rm -f bin/*
	if [ -e go/vendor ]; then rm -r go/vendor; fi  # Cleanup from old setup with vendor

gogen:
	$(MAKE) -C go/proto

ifndef GODEPS_SKIP
godeps: go_deps.bzl
else
godeps:
	@echo "godeps: skipped"
endif

go_deps.bzl: protobuf go.mod
	@tools/godeps.sh

protobuf: protobuf_clean
	bazel build //go/pkg/proto/control_plane:proto_srcs
	tar -kxf bazel-bin/go/pkg/proto/control_plane/proto_srcs.tar -C go/pkg/proto/control_plane
	chmod 0644 go/pkg/proto/control_plane/*.pb.go

	bazel build //go/pkg/proto/crypto:proto_srcs
	tar -kxf bazel-bin/go/pkg/proto/crypto/proto_srcs.tar -C go/pkg/proto/crypto
	chmod 0644 go/pkg/proto/crypto/*.pb.go

	bazel build //go/pkg/proto/discovery:proto_srcs
	tar -kxf bazel-bin/go/pkg/proto/discovery/proto_srcs.tar -C go/pkg/proto/discovery
	chmod 0644 go/pkg/proto/discovery/*.pb.go

	bazel build //go/pkg/proto/daemon:proto_srcs
	tar -kxf bazel-bin/go/pkg/proto/daemon/proto_srcs.tar -C go/pkg/proto/daemon
	chmod 0644 go/pkg/proto/daemon/*.pb.go

	bazel build //go/pkg/proto/gateway:proto_srcs
	tar -kxf bazel-bin/go/pkg/proto/gateway/proto_srcs.tar -C go/pkg/proto/gateway
	chmod 0644 go/pkg/proto/gateway/*.pb.go

protobuf_clean:
	rm -f go/pkg/proto/*/*.pb.go

bazel: godeps gogen
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

mocks: protobuf
	./tools/gomocks
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build $(GAZELLE_DIRS)

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build $(GAZELLE_DIRS)

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep ./bin/braccept

licenses:
	tools/licenses.sh
