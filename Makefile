.PHONY: all c clean go install

# Order is important:
C_DIRS = lib/libscion lib/libfilter sub/lwip-contrib endhost endhost/ssp
FILES = bin/dispatcher

all: c go

c:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var);)

clean:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var) clean;)
	$(foreach var,$(FILES),rm -f $(var);)

install:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var) install;)

uninstall:
	$(foreach var,$(C_DIRS),$(MAKE) -C $(var) uninstall;)

go:
	GOBIN=$$PWD/bin go install -v ./go/...
