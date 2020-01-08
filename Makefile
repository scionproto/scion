.PHONY: all clean godeps gogen mocks bazel gazelle setcap

BRACCEPT = bin/braccept

GAZELLE_MODE?=fix

BAZELRC?=.bazelrc

all: bazel

clean:
	bazel clean
	rm -f bin/*
	if [ -e go/vendor ]; then rm -r go/vendor; fi  # Cleanup from old setup with vendor

gogen:
ifndef GOGEN_SKIP
	$(MAKE) -C go/proto
else
	@echo "gogen: skipped"
endif

ifndef GODEPS_SKIP
godeps: go_deps.bzl
else
godeps:
	@echo "godeps: skipped"
endif

go_deps.bzl: go.mod
	@tools/godeps.sh

bazel: godeps gogen
	rm -f bin/*
	bazel --bazelrc=${BAZELRC} build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

mocks:
	./tools/gomocks

gazelle:
	bazel --bazelrc=${BAZELRC} run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build ./go

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep $(BRACCEPT)
