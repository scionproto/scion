.PHONY: all clean go clibs libscion libfilter liblwip libtcpmw libssocket dispatcher install uninstall goproto

SRC_DIRS = lib/libscion lib/libfilter endhost/ssp sub/lwip-contrib lib/tcp endhost go/proto

all: clibs dispatcher go

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)

go: goproto libscion
	GOBIN=$$PWD/bin go install -v ./go/...

gohsr: libhsr
	GOBIN=$$PWD/bin go install -tags hsr -v ./go/border/...
	sudo setcap cap_dac_read_search,cap_dac_override,cap_sys_admin,cap_net_raw+ep bin/border

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

goproto:
	$(MAKE) -C go/proto
