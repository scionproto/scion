.PHONY: all clean clibs libscion libfilter dispatcher uninstall tags vendor

SRC_DIRS = c/lib/scion c/lib/filter c/dispatcher

all: tags clibs dispatcher bazel

all-nofetch: tags clibs dispatcher bazel-nofetch

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	bazel clean
	rm -f bin/* tags

vendor:
	(cd go/vendor; ./vendor.sh)

WORKSPACE:
	./workspace.sh > WORKSPACE

bazel: vendor WORKSPACE
	# The second target is used provide python apps with go.capnp.
	# TODO: Remove it once python stuff is built by Bazel.
	bazel build //:scion //proto:go_capnp_copy
	tar -xf bazel-bin/scion.tar -C bin
	@sudo -p "go:braccept [sudo] password for %p: " true
	sudo setcap cap_net_admin,cap_net_raw+ep bin/braccept

bazel-nofetch:
	bazel build //:scion --fetch=false
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
