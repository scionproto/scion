.PHONY: all build build-dev dist-deb antlr clean docker-images gazelle go.mod licenses mocks protobuf scion-topo test test-integration write_all_source_files

build-dev:
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

build:
	rm -f bin/*
	bazel build //:scion
	tar -kxf bazel-bin/scion.tar -C bin

dist-deb:
	bazel build //dist:deb_all
	mkdir -p deb; rm -f deb/*;
	@ # Bazel cannot include the version in the filename, if we want to set it automatically from the git tag.
	@ # Extract the version from the .deb "control" manifest and expand the "__" in the filename to "_<version>_".
	@ #   See e.g. https://en.wikipedia.org/wiki/Deb_(file_format)#Control_archive
	@for f in `bazel cquery //dist:deb_all --output=files 2>/dev/null`; do \
		if [ -f "$$f" ]; then \
			bf=`basename $$f`; \
			v="$$(ar p $$f control.tar.gz | tar -xz --to-stdout ./control | sed -n 's/Version: //p')"; \
			bfv=$${bf%%__*}_$${v}_$${bf#*__}; \
			cp -v "$$f" deb/$$bfv; \
		fi \
	done

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

scrub:
	bazel clean --expunge
	rm -f bin/*

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

gazelle: go_deps.bzl
	bazel run //:gazelle --verbose_failures --config=quiet

licenses:
	tools/licenses.sh

antlr:
	antlr/generate.sh fix

write_all_source_files:
	bazel run //:write_all_source_files

.PHONY: lint lint-bazel lint-bazel-buildifier lint-doc lint-doc-mdlint lint-go lint-go-bazel lint-go-gazelle lint-go-golangci lint-go-semgrep lint-openapi lint-openapi-spectral lint-protobuf lint-protobuf-buf

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
	@tools/quiet bazel test --config lint

GO_BUILD_TAGS_ARG=$(shell bazel build --ui_event_filters=-stdout,-stderr --announce_rc --noshow_progress :dummy_setting 2>&1 | grep "'build' options" | sed -n "s/^.*--define gotags=\(\S*\).*/--build-tags \1/p" )

lint-go-golangci:
	$(info ==> $@)
	@if [ -t 1 ]; then tty=true; else tty=false; fi; \
		tools/quiet docker run --tty=$$tty --rm -v golangci-lint-modcache:/go -v golangci-lint-buildcache:/root/.cache -v "${PWD}:/src" -w /src golangci/golangci-lint:v1.54.2 golangci-lint run --config=/src/.golangcilint.yml --timeout=3m $(GO_BUILD_TAGS_ARG) --skip-dirs doc ./...

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
	@tools/quiet bazel run --config=quiet @buf_bin//file:buf -- check lint

lint-openapi: lint-openapi-spectral

lint-openapi-spectral:
	$(info ==> $@)
	@tools/quiet bazel run --config=quiet //:spectral -- lint --ruleset ${PWD}/spec/.spectral.yml ${PWD}/spec/*.gen.yml

lint-doc: lint-doc-mdlint

lint-doc-mdlint:
	$(info ==> $@)
	@FILES=$$(find -type f -iname '*.md' -not -path "./private/mgmtapi/tools/node_modules/*" -not -path "./.github/**/*" | grep -vf tools/md/skipped); \
		docker run --rm -v ${PWD}:/data -v ${PWD}/tools/md/mdlintstyle.rb:/style.rb $$(docker build -q tools/md) $${FILES} -s /style.rb
