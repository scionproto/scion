#!/bin/bash -e

SRC_DIR="$(dirname "$(readlink -f "$0")")"

if [ -z "$TMPDIR" ]; then
	echo "Creating temporary directory"
	TMPDIR=$(mktemp -d)
fi
echo "Setting up gopath in $TMPDIR"
mkdir -p $TMPDIR/go/src/github.com/scionproto/scion
mkdir -p $TMPDIR/go/bin
export GOPATH=$TMPDIR/go
export GOBIN=$GOPATH/bin
export PATH=$PATH:/usr/lib/go-1.9/bin:$GOBIN

echo "Go environment:"
go env

echo "Installing govendor"
go get -u github.com/kardianos/govendor

echo "Copying source code"
cp -r $SRC_DIR/* $GOPATH/src/github.com/scionproto/scion
ls $GOPATH/src/github.com/scionproto/scion

echo "Compiling code"
(cd $GOPATH/src/github.com/scionproto/scion/go && make)

echo "Copying back binaries"
(cd $GOPATH/src/github.com/scionproto/scion/bin && cp * $SRC_DIR/bin)

echo "Cleaning up"
rm -rf $TMPDIR
