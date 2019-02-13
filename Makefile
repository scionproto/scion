.PHONY: all clean go clibs libscion libfilter dispatcher uninstall tags

SRC_DIRS = c/lib/scion c/lib/filter c/dispatcher

all: tags clibs dispatcher go

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	cd go && $(MAKE) clean
	rm -f bin/* tags

go:
	@# `make -C go` breaks if there are symlinks in $PWD
	cd go && $(MAKE)

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
