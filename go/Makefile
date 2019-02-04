.PHONY: lint

LOCAL_DIRS = $(shell find * -maxdepth 0 -type d | grep -v '^bazel-.*')
LOCAL_PKGS = $(patsubst %, ./%/..., $(LOCAL_DIRS))

lint:
	#@echo "======> Building lint tools"
	bazel build //:lint
	tar -xf ../bazel-bin/lint.tar -C ../bin
	@echo "======> impi"
	@# Skip CGO (https://github.com/pavius/impi/issues/5) files.
	../bin/impi --local github.com/scionproto/scion --scheme stdThirdPartyLocal --skip '/c\.go$$' ./...
	@echo "======> gofmt"
	out=$$(gofmt -d -s ${LOCAL_DIRS}); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi
	@echo "======> linelen (lll)"
	out=$$(find . -type f -iname '*.go' -a '!' '(' -ipath './lib/pathpol/sequence/*' ')' | ../bin/lll -w 4 -l 100 --files -e '`comment:"|`ini:"|https?:'); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi
	@echo "======> go vet"
	go vet ${LOCAL_PKGS}
	@echo "======> misspell"
	../bin/misspell -error ${LOCAL_DIRS}
