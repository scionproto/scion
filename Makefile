
.PHONY: all bazel clean gazelle gogen licenses mocks protobuf antlr lint
.NOTPARALLEL:

GAZELLE_MODE?=fix
GAZELLE_DIRS=./go ./acceptance

build: bazel

# all: performs the code-generation steps and then builds; the generated code
# is git controlled, and therefore this is only necessary when changing the
# sources for the code generation.
# Note: built in correct order, because .NOTPARALLEL.
all: go_deps.bzl gogen protobuf mocks gazelle licenses build antlr

clean:
	bazel clean
	rm -f bin/*

bazel:
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

test:
	bazel test --config=unit --test_output=errors

go_deps.bzl: go.mod
	@tools/godeps.sh

gogen:
	$(MAKE) -C go/proto

protobuf:
	rm -rf bazel-bin/go/pkg/proto/*/go_default_library_/github.com/scionproto/scion/go/pkg/proto/*
	bazel build --output_groups=go_generated_srcs //go/pkg/proto/...
	rm -f go/pkg/proto/*/*.pb.go
	cp -r bazel-bin/go/pkg/proto/*/go_default_library_/github.com/scionproto/scion/go/pkg/proto/* go/pkg/proto
	cp -r bazel-bin/go/pkg/proto/*/*/go_default_library_/github.com/scionproto/scion/go/pkg/proto/* go/pkg/proto
	chmod 0644 go/pkg/proto/*/*.pb.go

oai-boilerplate: clean
	bazel build //spec/...

	rm -f go/pkg/cs/api/*.gen.go
	cp -r bazel-bin/spec/go/pkg/cs/api/*.gen.go go/pkg/cs/api
	chmod 0644 go/pkg/cs/api/*.gen.go

	rm -f go/pkg/ca/api/*.gen.go
	cp -r bazel-bin/spec/go/pkg/ca/api/*.gen.go go/pkg/ca/api
	chmod 0644 go/pkg/ca/api/*.gen.go

mocks:
	tools/gomocks

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -go_naming_convention go_default_library -exclude docker/_build $(GAZELLE_DIRS)

licenses:
	tools/licenses.sh

antlr:
	antlr/generate.sh $(GAZELLE_MODE)
lint:
	./scion.sh lint
