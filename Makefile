.PHONY: all clean clibs libscion libfilter dispatcher uninstall tags vendor

SRC_DIRS = c/lib/scion c/lib/filter c/dispatcher

all: tags clibs dispatcher bazel

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	bazel clean
	rm -f bin/* tags

vendor:
	./tools/vendor.sh

bazel: vendor
	bazel build //:scion
	tar -xf bazel-bin/scion.tar -C bin
	@sudo -p "go:braccept [sudo] password for %p: " true
	sudo setcap cap_net_admin,cap_net_raw+ep bin/braccept

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
	which ctags >/dev/null 2>&1 || exit 0; git ls-files | ctags -L -
