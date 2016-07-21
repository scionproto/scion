.PHONY: all clean clibs clibs_install dispatcher clean go install

# Order is important:
CLIB_DIRS = lib/libscion lib/libfilter lib/tcp sub/lwip-contrib endhost/ssp

all: clibs dispatcher go

clean:
	$(foreach var,$(CLIB_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	$(MAKE) -C endhost clean

clibs:
	$(foreach var,$(CLIB_DIRS),$(MAKE) -C $(var) || exit 1;)

clibs_install:
	$(foreach var,$(CLIB_DIRS),$(MAKE) -C $(var) install || exit 1;)

dispatcher: clibs_install
	$(MAKE) -C endhost

install: clibs_install
	$(MAKE) -C endhost install

uninstall:
	$(foreach var,$(CLIB_DIRS),$(MAKE) -C $(var) uninstall || exit 1;)
	$(MAKE) -C endhost uninstall

go:
	GOBIN=$$PWD/bin go install -v ./go/...
