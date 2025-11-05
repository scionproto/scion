#!/bin/sh

if [ "$(basename "$PWD")" = "scion" ]; then
    cd nat-tester || return
fi

if [ "$(basename "$PWD")" != "nat-tester" ]; then
    echo "This script must be run from within the scion directory"
    exit 1
fi

CGO_ENABLED=0 go build -o "test-server" ./test-server.go
CGO_ENABLED=0 go build -o "snet-test-client" ./snet-test-client.go

echo "build complete"
