.PHONY: all clean goenv gogenlinks gogenlinks_clean vendor bazel gazelle setcap clibs libscion libfilter dispatcher uninstall tags

BRACCEPT = bin/braccept

GAZELLE_MODE?=fix

SRC_DIRS = c/lib/scion c/lib/filter c/dispatcher

all: tags clibs dispatcher bazel

clean: gogenlinks_clean
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	bazel clean
	rm -f bin/* tags
	if [ -e go/vendor ]; then rm -r go/vendor; fi

goenv: vendor gogenlinks

gogenlinks: gogenlinks_clean
	bazel build //go/proto:go_default_library
	find bazel-genfiles/go/proto -maxdepth 1 -type f -exec ln -snf ../../{} go/proto \;

gogenlinks_clean:
	find ./go/proto -maxdepth 1 -type l -exec rm {} +

vendor:
	./tools/vendor.sh

bazel: vendor
	bazel build //:scion //:scion-ci --workspace_status_command=./tools/bazel-build-env
	rm -f bin/*
	tar -kxf bazel-bin/scion.tar -C bin
	tar -kxf bazel-bin/scion-ci.tar -C bin

gazelle:
	bazel run //:gazelle -- update -mode=$(GAZELLE_MODE) -index=false -external=external -exclude go/vendor -exclude docker/_build ./go

setcap:
	tools/setcap cap_net_admin,cap_net_raw+ep $(BRACCEPT)

# Order is important
clibs: libscion libfilter

libscion:
	$(MAKE) -C c/lib/scion install

libfilter: libscion
	$(MAKE) -C c/lib/filter install

dispatcher: clibs
	$(MAKE) -C c/dispatcher install

uninstall:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) uninstall || exit 1;)

tags:
	which ctags >/dev/null 2>&1 || exit 0; git ls-files c | ctags -L -
