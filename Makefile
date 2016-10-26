.PHONY: all clean go gohsr clibs libscion libfilter liblwip libtcpmw libssocket dispatcher libhsr install uninstall

SRC_DIRS = lib/libscion lib/libfilter endhost/ssp sub/lwip-contrib lib/tcp endhost

all: clibs dispatcher go

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	if type -P go >/dev/null; then cd go && make clean; fi

go: libscion
	# `make -C go` breaks if there are symlinks in $PWD
	cd go && make

gohsr: libhsr
	cd go && make hsr

# Order is important
clibs: libscion libfilter libssocket liblwip libtcpmw

libscion:
	$(MAKE) -C lib/libscion install

libfilter: libscion
	$(MAKE) -C lib/libfilter install

liblwip: libscion
	$(MAKE) -C sub/lwip-contrib install

libtcpmw: libscion liblwip
	$(MAKE) -C lib/tcp install

libssocket: libscion
	$(MAKE) -C endhost/ssp install

dispatcher: clibs
	$(MAKE) -C endhost install

libhsr: libscion
	$(MAKE) -C lib/libhsr doinstall

install: clibs dispatcher

uninstall:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) uninstall || exit 1;)
