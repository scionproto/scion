.PHONY: all antlr bazel build clean docker-images gazelle golangci-lint licenses lint mocks protobuf scion-topo test test-acceptance

.NOTPARALLEL:

GAZELLE_MODE?=fix
GAZELLE_DIRS=.

build: bazel

# all: performs the code-generation steps and then builds; the generated code
# is git controlled, and therefore this is only necessary when changing the
# sources for the code generation.
# Note: built in correct order, because .NOTPARALLEL.
all: go_deps.bzl protobuf mocks gazelle licenses build antlr

clean:
	bazel clean
	rm -f bin/*

bazel:
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

test:
	bazel test --config=unit_all

test-integration:
	bazel test --config=integration_all

go_deps.bzl: go.mod
	bazel run //:gazelle -- update-repos -prune -from_file=go.mod -to_macro=go_deps.bzl%go_deps
	@# XXX(matzf): clean up; gazelle update-repose inconsistently inserts blank lines (see bazelbuild/bazel-gazelle#1088).
	@sed -e '/def go_deps/,$${/^$$/d}' -i go_deps.bzl

docker-images:
	@echo "Build perapp images"
	bazel run //docker:prod
	@echo "Build scion tester"
	bazel run //docker:test

scion-topo:
	bazel build //:scion-topo
	tar --overwrite -xf bazel-bin/scion-topo.tar -C bin

protobuf:
	rm -rf bazel-bin/pkg/proto/*/go_default_library_/github.com/scionproto/scion/pkg/proto/*
	bazel build --output_groups=go_generated_srcs //pkg/proto/...
	rm -f pkg/proto/*/*.pb.go
	cp -r bazel-bin/pkg/proto/*/go_default_library_/github.com/scionproto/scion/pkg/proto/* pkg/proto
	cp -r bazel-bin/pkg/proto/*/*/go_default_library_/github.com/scionproto/scion/pkg/proto/* pkg/proto
	chmod 0644 pkg/proto/*/*.pb.go

mocks:
	tools/gomocks.py

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -go_naming_convention go_default_library $(GAZELLE_DIRS)

licenses:
	tools/licenses.sh

antlr:
	antlr/generate.sh $(GAZELLE_MODE)

lint:
	tools/lint.sh

golangci-lint:
	docker run --rm -v "${PWD}:/src" -w /src golangci/golangci-lint:v1.43.0 golangci-lint run --config=/src/.golangcilint.yml --timeout=3m --skip-dirs doc ./...
