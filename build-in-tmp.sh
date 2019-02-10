#!/bin/bash -e

SRC_DIR="$(dirname "$(readlink -f "$0")")"

rm -rf ${SRC_DIR}/bin/*

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

echo "Source dir: $SRC_DIR"
echo "Go environment:"
go env

eval $(go env | sed -r 's/^(set )?(\w+)=("?)(.*)\3$/\2="\4"/gm')

TARGETGOOS=${CROSS_GOOS:-$GOOS}
TARGETGOARCH=${CROSS_GOARCH:-$GOARCH}

echo 'Architectures'
echo "$GOHOSTOS -> $TARGETGOOS"
echo "$GOHOSTARCH -> $TARGETGOARCH"

echo "Installing govendor"
go get -u github.com/kardianos/govendor

echo "Copying source code"
cp -r $SRC_DIR/* $GOPATH/src/github.com/scionproto/scion
ls $GOPATH/src/github.com/scionproto/scion

export GOOS=$TARGETGOOS
export GOARCH=$TARGETGOARCH
export HOSTCC=$(which cc)

 #This needs some explanations
# We need to compile deps and proto for the native architecture (e.g. to have a valid capnp binary)
# Then switch over to our cross compile target and compile for this.
echo "Compiling code"
(cd $GOPATH/src/github.com/scionproto/scion/go && GOOS=$GOHOSTOS GOARCH=$GOHOSTARCH CC=$HOSTCC make deps_gen && make bin GOBIN=$GOBIN GOPATH=$GOPATH GOOS=$TARGETGOOS GOARCH=$TARGETGOARCH)

echo "Copying back binaries"
(cd $GOPATH/src/github.com/scionproto/scion/bin && cp * $SRC_DIR/bin)

echo "Copying back go.capnp"
(cd $GOPATH/src/github.com/scionproto/scion/go && cp vendor/zombiezen.com/go/capnproto2/std/go.capnp $SRC_DIR/proto/go.capnp)

echo "Cleaning up"
rm -rf $TMPDIR
