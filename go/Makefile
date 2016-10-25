.PHONY: all clean test coverage fmt deps_proto deps depspurge proto bin libs hsr

LOCAL_DIRS = $(shell find * -maxdepth 0 -type d | grep -v '^vendor$$')
LOCAL_PKGS = $(patsubst %, ./%/..., $(LOCAL_DIRS))
LOCAL_GOBIN = $(shell realpath -s $$PWD/../bin)

all: deps_proto bin

clean:
	rm -f gocover.html vendor/.deps.stamp
	GOBIN=${LOCAL_GOBIN} go clean ${LOCAL_PKGS}
	go clean -i ./vendor/...
	cd proto && $(MAKE) clean

test: deps_proto
	govendor test +local

coverage: deps_proto
	gocov test ${LOCAL_PKGS} | gocov-html > gocover.html
	@echo
	@echo "Go coverage report here: file://$$PWD/gocover.html"

fmt:
	gofmt -d -s ${LOCAL_DIRS}

deps_proto: proto

deps: vendor/.deps.stamp

vendor/.deps.stamp: vendor/vendor.json 
	govendor sync
	go install -v ./vendor/...
	touch $@

depspurge:
	rm -f vendor/.deps.stamp
	go clean -i ./vendor/...
	find vendor/* -maxdepth 0 -type d -exec rm -rf ./{} \;

proto: deps
	cd proto && $(MAKE)

bin: deps_proto
	GOBIN=${LOCAL_GOBIN} govendor install -v +local,program

libs: deps_proto
	govendor install -v +local,^program

hsr: libs
	GOBIN=${LOCAL_GOBIN} go install -v -tags hsr ./border/...
	sudo setcap cap_dac_read_search,cap_dac_override,cap_sys_admin,cap_net_raw+ep ../bin/border
