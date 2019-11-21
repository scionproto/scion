.PHONY: all clean godeps gogen mocks bazel gazelle setcap

BRACCEPT = bin/braccept

GAZELLE_MODE?=fix

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
	bazel run //:gazelle -- update-repos -from_file=go.mod -to_macro=go_deps.bzl%go_deps -prune

bazel: godeps gogen
	rm -f bin/*
	bazel build //:scion //:scion-ci
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

mocks:
	./tools/gomocks

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build ./go

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep $(BRACCEPT)
