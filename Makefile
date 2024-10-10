.PHONY: all build build-dev dist-deb antlr clean docker-images gazelle go.mod licenses mocks protobuf scion-topo test test-integration write_all_source_files git-version

build-dev:
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

build:
	rm -f bin/*
	bazel build //:scion
	tar -kxf bazel-bin/scion.tar -C bin

# BFLAGS is optional. It may contain additional command line flags for CI builds. Currently this is:
# "--file_name_version=$(tools/git-version)" to include the git version in the artifacts names.
dist-deb:
	bazel build //dist:deb_all $(BFLAGS)
	@ # These artefacts have unique names but varied locations. Link them somewhere convenient.
	@ mkdir -p installables
	@ cd installables ; ln -sfv ../bazel-out/*/bin/dist/*.deb .

dist-openwrt:
	bazel build //dist:openwrt_all $(BFLAGS)
	@ # These artefacts have unique names but varied locations. Link them somewhere convenient.
	@ mkdir -p installables
	@ cd installables ; ln -sfv ../bazel-out/*/bin/dist/*.ipk .

dist-openwrt-testing:
	bazel build //dist:openwrt_testing_all $(BFLAGS)
	@ # These artefacts have unique names but varied locations. Link them somewhere convenient.
	@ mkdir -p installables
	@ cd installables ; ln -sfv ../bazel-out/*/bin/dist/*.ipk .

dist-rpm:
	bazel build //dist:rpm_all $(BFLAGS)
	@ # These artefacts have unique names but varied locations. Link them somewhere convenient.
	@ mkdir -p installables
	@ cd installables ; ln -sfv ../bazel-out/*/bin/dist/*.rpm .

# all: performs the code-generation steps and then builds; the generated code
# is git controlled, and therefore this is only necessary when changing the
# sources for the code generation.
# Use NOTPARALLEL to force correct order.
# Note: From GNU make 4.4, this still allows building any other targets (e.g. lint) in parallel.
.NOTPARALLEL: all
all: go_deps.bzl protobuf mocks gazelle build-dev antlr write_all_source_files licenses

clean:
	bazel clean
	rm -f bin/*
	docker image ls --filter label=org.scion -q | xargs --no-run-if-empty docker image rm

scrub:
	bazel clean --expunge
	rm -f bin/*
	rm -f installables/*

test:
	bazel test --config=unit_all

test-integration:
	bazel test --config=integration_all

go.mod:
	bazel run --config=quiet @go_sdk//:bin/go -- mod tidy

go_deps.bzl: go.mod
	bazel run --verbose_failures --config=quiet //:gazelle_update_repos
	@# XXX(matzf): clean up; gazelle update-repose inconsistently inserts blank lines (see bazelbuild/bazel-gazelle#1088).
	@sed -e '/def go_deps/,$${/^$$/d}' -i go_deps.bzl

docker-images:
	@echo "Build images"
	bazel build //docker:prod //docker:test
	@echo "Load images"
	@bazel cquery '//docker:prod union //docker:test' --output=files 2>/dev/null | xargs -I{} docker load --input {}

scion-topo:
	bazel build //:scion-topo
	tar --overwrite -xf bazel-bin/scion-topo.tar -C bin

protobuf:
	rm -rf bazel-bin/pkg/proto/*/go_default_library_/github.com/scionproto/scion/pkg/proto/*
	bazel build --output_groups=go_generated_srcs //pkg/proto/...
	rm -f pkg/proto/*/*.pb.go
	cp -r bazel-bin/pkg/proto/*/go_default_library_/github.com/scionproto/scion/pkg/proto/* pkg/proto
	cp -r bazel-bin/pkg/proto/*/*/go_default_library_/github.com/scionproto/scion/pkg/proto/* pkg/proto
	chmod 0644 pkg/proto/*/*.pb.go pkg/proto/*/*/*.pb.go

mocks:
	tools/gomocks.py

gazelle: go_deps.bzl
	bazel run //:gazelle --verbose_failures --config=quiet
	./tools/buildrill/go_integration_test_sync

licenses:
	tools/licenses.sh

antlr:
	antlr/generate.sh fix

write_all_source_files:
	bazel run //:write_all_source_files

.PHONY: lint lint-bazel lint-bazel-buildifier lint-doc lint-doc-mdlint lint-doc-sphinx lint-go lint-go-bazel lint-go-gazelle lint-go-golangci lint-go-semgrep lint-openapi lint-openapi-spectral lint-protobuf lint-protobuf-buf

# Enable --keep-going if all goals specified on the command line match the pattern "lint%"
ifeq ($(filter-out lint%, $(MAKECMDGOALS)), )
MAKEFLAGS+=--keep-going
endif

lint: lint-go lint-bazel lint-protobuf lint-openapi lint-doc

lint-go: lint-go-gazelle lint-go-bazel lint-go-golangci lint-go-semgrep

lint-go-gazelle:
	$(info ==> $@)
	bazel run //:gazelle_diff --verbose_failures --config=quiet

lint-go-bazel:
	$(info ==> $@)
	@tools/quiet bazel test --config lint //...

GO_BUILD_TAGS_ARG=$(shell bazel info --ui_event_filters=-stdout,-stderr --announce_rc --noshow_progress 2>&1 | grep "'build' options" | sed -n "s/^.*--define gotags=\(\S*\).*/--build-tags \1/p" )

lint-go-golangci:
	$(info ==> $@)
	@if [ -t 1 ]; then tty=true; else tty=false; fi; \
		tools/quiet docker run --tty=$$tty --rm -v golangci-lint-modcache:/go -v golangci-lint-buildcache:/root/.cache -v "${PWD}:/src" -w /src golangci/golangci-lint:v1.60.3 golangci-lint run --config=/src/.golangcilint.yml --timeout=3m $(GO_BUILD_TAGS_ARG) --skip-dirs doc ./...

lint-go-semgrep:
	$(info ==> $@)
	@if [ -t 1 ]; then tty=true; else tty=false; fi; \
		tools/quiet docker run --tty=$$tty --rm -v "${PWD}:/src" returntocorp/semgrep@sha256:3bef9d533a44e6448c43ac38159d61fad89b4b57f63e565a8a55ca265273f5ba semgrep --config=/src/tools/lint/semgrep --error

lint-bazel: lint-bazel-buildifier lint-bazel-writeall

lint-bazel-buildifier:
	$(info ==> $@)
	@tools/quiet bazel run --config=quiet //:buildifier_check

lint-bazel-writeall:
	$(info ==> $@)
	@tools/quiet ./tools/lint/write_source_files_sync

lint-protobuf: lint-protobuf-buf

lint-protobuf-buf:
	$(info ==> $@)
	@tools/quiet bazel run --config=quiet @buf//:buf -- lint $(PWD) --path $(PWD)/proto

lint-openapi: lint-openapi-spectral

lint-openapi-spectral:
	$(info ==> $@)
	@tools/quiet bazel run --config=quiet //:spectral -- lint --ruleset ${PWD}/spec/.spectral.yml ${PWD}/spec/*.gen.yml

lint-doc: lint-doc-mdlint lint-doc-sphinx

lint-doc-mdlint:
	$(info ==> $@)
	@if [ -t 1 ]; then tty=true; else tty=false; fi; \
		tools/quiet docker run --tty=$$tty --rm -v ${PWD}:/workdir davidanson/markdownlint-cli2:v0.12.1

lint-doc-sphinx:
	$(info ==> $@)
	@tools/quiet bazel test --config=lint //doc:sphinx_lint_test
