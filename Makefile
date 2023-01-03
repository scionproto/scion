.PHONY: all antlr bazel build clean docker-images gazelle licenses mocks protobuf scion-topo test test-acceptance

GAZELLE_MODE?=fix
GAZELLE_DIRS=.

build: bazel

# all: performs the code-generation steps and then builds; the generated code
# is git controlled, and therefore this is only necessary when changing the
# sources for the code generation.
# Use NOTPARALLEL to force correct order.
# Note: From GNU make 4.4, this still allows building any other targets (e.g. lint) in parallel.
.NOTPARALLEL: all
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
	bazel run //:gazelle --config=quiet -- update -mode=$(GAZELLE_MODE) -go_naming_convention go_default_library $(GAZELLE_DIRS)

licenses:
	tools/licenses.sh

antlr:
	antlr/generate.sh $(GAZELLE_MODE)

.PHONY: lint lint-bazel lint-bazel-buildifier lint-doc lint-doc-mdlint lint-go lint-go-bazel lint-go-gazelle lint-go-golangci lint-go-semgrep lint-openapi lint-openapi-spectral lint-protobuf lint-protobuf-buf

# Enable --keep-going if all goals specified on the command line match the pattern "lint%"
ifeq ($(filter-out lint%, $(MAKECMDGOALS)), )
MAKEFLAGS+=--keep-going
endif

lint: lint-go lint-bazel lint-protobuf lint-openapi lint-doc

lint-go: lint-go-gazelle lint-go-bazel lint-go-golangci lint-go-semgrep

lint-go-gazelle:
	$(info ==> $@)
	@$(MAKE) -s gazelle GAZELLE_MODE=diff

lint-go-bazel:
	$(info ==> $@)
	@tools/quiet bazel test --config lint

lint-go-golangci:
	$(info ==> $@)
	@if [ -t 1 ]; then tty=true; else tty=false; fi; \
		tools/quiet docker run --tty=$$tty --rm -v golangci-lint-modcache:/go -v golangci-lint-buildcache:/root/.cache -v "${PWD}:/src" -w /src golangci/golangci-lint:v1.50.0 golangci-lint run --config=/src/.golangcilint.yml --timeout=3m --skip-dirs doc ./...

lint-go-semgrep:
	$(info ==> $@)
	@if [ -t 1 ]; then tty=true; else tty=false; fi; \
		tools/quiet docker run --tty=$$tty --rm -v "${PWD}:/src" returntocorp/semgrep@sha256:3bef9d533a44e6448c43ac38159d61fad89b4b57f63e565a8a55ca265273f5ba semgrep --config=/src/tools/lint/semgrep --error

lint-bazel: lint-bazel-buildifier

lint-bazel-buildifier:
	$(info ==> $@)
	@tools/quiet bazel run --config=quiet //:buildifier_check

lint-protobuf: lint-protobuf-buf

lint-protobuf-buf:
	$(info ==> $@)
	@tools/quiet bazel run --config=quiet @buf_bin//file:buf -- check lint

lint-openapi: lint-openapi-spectral

lint-openapi-spectral:
	$(info ==> $@)
	@tools/quiet bazel run --config=quiet @rules_openapi_npm//@stoplight/spectral-cli/bin:spectral -- lint --ruleset ${PWD}/spec/.spectral.yml ${PWD}/spec/*.gen.yml

lint-doc: lint-doc-mdlint

lint-doc-mdlint:
	$(info ==> $@)
	@FILES=$$(find -type f -iname '*.md' -not -path "./rules_openapi/tools/node_modules/*" -not -path "./.github/**/*" | grep -vf tools/md/skipped); \
		docker run --rm -v ${PWD}:/data -v ${PWD}/tools/md/mdlintstyle.rb:/style.rb $$(docker build -q tools/md) $${FILES} -s /style.rb
