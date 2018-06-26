.PHONY: all clean go gohsr clibs libscion libfilter dispatcher libhsr uninstall tags

SRC_DIRS = c/lib/scion c/lib/filter c/dispatcher

all: clibs dispatcher go

clean:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) clean || exit 1;)
	cd go && $(MAKE) clean
	rm -f bin/*

go: libscion
	@# `make -C go` breaks if there are symlinks in $PWD
	cd go && $(MAKE)

gohsr: libhsr
	cd go && $(MAKE) hsr

# Order is important
clibs: libscion libfilter

libscion:
	$(MAKE) -C c/lib/scion install

libfilter: libscion
	$(MAKE) -C c/lib/filter install

dispatcher: clibs
	$(MAKE) -C c/dispatcher install

libhsr: libscion
	$(MAKE) -C c/lib/hsr doinstall

uninstall:
	$(foreach var,$(SRC_DIRS),$(MAKE) -C $(var) uninstall || exit 1;)
