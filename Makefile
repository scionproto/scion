.PHONY: all clean go gohsr clibs libscion libfilter liblwip libtcpmw libssocket dispatcher libhsr uninstall tags

SRC_DIRS = c/lib/scion c/lib/filter c/ssp sub/lwip-contrib c/lib/tcp c/dispatcher

all: clibs dispatcher go

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	cd go && $(MAKE) clean
	rm -f tags

go: libscion
	@# `make -C go` breaks if there are symlinks in $PWD
	cd go && $(MAKE)

gohsr: libhsr
	cd go && $(MAKE) hsr

# Order is important
clibs: libscion libfilter liblwip libtcpmw

libscion:
	$(MAKE) -C c/lib/scion install

libfilter: libscion
	$(MAKE) -C c/lib/filter install

liblwip: libscion
	$(MAKE) -C sub/lwip-contrib install

libtcpmw: libscion liblwip
	$(MAKE) -C c/lib/tcp install

libssocket: libscion
	$(MAKE) -C c/ssp install

dispatcher: clibs
	$(MAKE) -C c/dispatcher install

libhsr: libscion
	$(MAKE) -C c/lib/hsr doinstall

uninstall:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) uninstall || exit 1;)

tags:
	{ git ls-files; git submodule --quiet foreach 'git ls-files | sed "s|^|$$path/|"'; } | grep -v sub/web/ad_manager/static/js/ | ctags -L -
