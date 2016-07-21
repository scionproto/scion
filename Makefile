.PHONY: all c clean go install

# Order is important:
C_DIRS = lib/libscion lib/libfilter sub/lwip-contrib endhost endhost/ssp
FILES = bin/dispatcher

all: c go

c:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var) || exit 1;)

clean:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	$(foreach var,$(FILES),rm -f $(var);)

install:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var) install || exit 1;)

uninstall:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var) uninstall || exit 1;)

go:
	GOBIN=$$PWD/bin go install -v ./go/...
