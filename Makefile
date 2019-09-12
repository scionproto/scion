.PHONY: all clean goenv gogen vendor mocks bazel bazel_bin_clean gazelle setcap tags

BRACCEPT = bin/braccept

GAZELLE_MODE?=fix

all: tags bazel

clean:
	bazel clean
	rm -f bin/* tags
	if [ -e go/vendor ]; then rm -r go/vendor; fi

gogen:
ifndef GOGEN_SKIP
	$(MAKE) -C go/proto
else
	@echo "gogen: skipped"
endif

goenv: vendor
	bazel fetch "kind('go_(default_library|test|binary)', //...)"

vendor:
	if [ -e go/vendor ]; then rm -r go/vendor; fi
	bzlcompat -vendorBase=go

bazel: vendor gogen bazel_bin_clean
	bazel build //:scion //:scion-ci --workspace_status_command=./tools/bazel-build-env
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

# Delete everything in bin/ that isn't a hidden file,
# as those aren't created by bazel.
bazel_bin_clean:
	find bin/ -mindepth 1 ! -iname ".*" -exec rm {} +

mocks: goenv
	./tools/gomocks

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build ./go

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep $(BRACCEPT)

tags:
	which ctags >/dev/null 2>&1 || exit 0; git ls-files c | ctags -L -
