.PHONY: all clean go clibs libscion libfilter liblwip libtcpmw libssocket dispatcher install uninstall

SRC_DIRS = lib/libscion lib/libfilter endhost/ssp sub/lwip-contrib lib/tcp endhost

all: go clibs dispatcher

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)

go:
	GOBIN=$$PWD/bin go install -v ./go/...

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

install: clibs dispatcher

uninstall:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) uninstall || exit 1;)

