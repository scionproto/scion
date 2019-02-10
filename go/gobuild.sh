#!/bin/bash -e

if [ "$GOOS" != "$GOHOSTOS" ] || [ "$GOARCH" != "$GOHOSTARCH" ]; then
  PKGS=$(find . -name main.go -exec bash -c 'echo $(dirname {})' \;)
  for pkg in ${PKGS}; do
    echo "Building $pkg"
    CGO_ENABLED=1 go build -tags 'assert' -v -o $(pwd)/../bin/$(basename $pkg) ./$pkg >> /tmp/buildlog 2>&1 && echo "DONE" || echo "FAILED"
  done
else
  GOBIN=${LOCAL_GOBIN} govendor install --tags "${GOTAGS}" -v +local,program
fi
