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
	bazel build --output_groups=go_generated_srcs //go/pkg/proto/...
	rm -f go/pkg/proto/*/*.pb.go
	cp -r bazel-bin/go/pkg/proto/*/go_default_library_/github.com/scionproto/scion/go/pkg/proto/* go/pkg/proto
	chmod 0644 go/pkg/proto/*/*.pb.go

mocks:
	tools/gomocks

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build $(GAZELLE_DIRS)

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep ./bin/braccept

licenses:
	tools/licenses.sh
