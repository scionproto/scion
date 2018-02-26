.PHONY: all clean test coverage lint deps_proto deps depspurge proto bin libs hsr

SHELL=/bin/bash
LOCAL_DIRS = $(shell find * -maxdepth 0 -type d | grep -v '^vendor$$')
LOCAL_PKGS = $(patsubst %, ./%/..., $(LOCAL_DIRS))
LOCAL_GOBIN = $(shell realpath -s $$PWD/../bin)
LOCAL_NONGEN = $(shell find ${LOCAL_DIRS} -type f -iname '*.go' -a '!' -iname '*.capnp.go')
GOTAGS = assert

all: deps_proto bin libs

clean:
	rm -f gocover.html vendor/.deps.stamp
	GOBIN=${LOCAL_GOBIN} go clean ${LOCAL_PKGS}
	go clean -i ./vendor/...
	cd proto && $(MAKE) clean

test: deps_proto
	GOCONVEY_REPORTER=story govendor test +local

test_running: deps_proto
	GOCONVEY_REPORTER=story govendor test +local -tags infrarunning

coverage: deps_proto
	set -o pipefail; GOCONVEY_REPORTER=story gocov test ${LOCAL_PKGS} | gocov-html > gocover.html
	@echo
	@echo "Go coverage report here: file://$$PWD/gocover.html"

lint:
	@echo "======> goimports"
	out=$$(goimports -d -local github.com/scionproto ${LOCAL_NONGEN}); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi
	@echo "======> gofmt"
	out=$$(gofmt -d -s ${LOCAL_DIRS}); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi
	@echo "======> go vet"
	go vet ${LOCAL_PKGS}

deps_proto: deps proto

deps: vendor/.deps.stamp ../proto/go.capnp

vendor/.deps.stamp: vendor/vendor.json
	@[ -z "${QUIET}" ] && echo "$$(date -Iseconds) Remove unused deps"; \
	    govendor list -no-status +unused | while read pkg; do \
	    grep -q '"path": "'$$pkg'"' vendor/vendor.json && continue; \
	    echo "$$pkg"; \
	    govendor remove "$$pkg"; \
	done
	@[ -z "${QUIET}" ] && echo "$$(date -Iseconds) Syncing deps"; govendor sync -v
	@[ -z "${QUIET}" ] && echo "$$(date -Iseconds) Installing deps"; go install ./vendor/...
	@if [ -n "$$(govendor list -no-status +outside | grep -v '^context$$')" ]; then \
	    echo "ERROR: external/missing packages:"; \
	    govendor list +outside; \
	    exit 1; \
	fi;
	touch $@

../proto/go.capnp:
	cp vendor/zombiezen.com/go/capnproto2/std/go.capnp ../proto/go.capnp

depspurge:
	rm -f vendor/.deps.stamp
	go clean -i ./vendor/...
	find vendor/* -maxdepth 0 -type d -exec rm -rf ./{} \;

proto: deps
	$(MAKE) -C proto

bin: deps_proto
	GOBIN=${LOCAL_GOBIN} govendor install --tags "$(GOTAGS)" -v +local,program

libs: deps_proto
	govendor install --tags "$(GOTAGS)" -v +local,^program

hsr: libs
	GOBIN=${LOCAL_GOBIN} go install -v -tags "$(GOTAGS) hsr" ./border/...
	sudo setcap cap_dac_read_search,cap_dac_override,cap_sys_admin,cap_net_raw+ep ../bin/border
