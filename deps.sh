#!/bin/bash

set -e

cmd_all() {
    cmd_pkgs
    cmd_pip
    cmd_pipweb
    cmd_zlog
    cmd_golang
    cmd_misc
}

cmd_pkgs() {
    if [ -e /etc/debian_version ]; then
        pkgs_debian
    else
        echo "As this is not a debian-based OS, please install the equivalents of these packages:"
        cat pkgs_debian.txt
    fi
}

pkgs_debian() {
    local pkgs=""
    echo "Checking for necessary debian packages"
    for pkg in $(< pkgs_debian.txt); do
        pkg_deb_chk $pkg || pkgs+="$pkg "
    done
    if [ -n "$pkgs" ]; then
        echo "Installing missing necessary packages: $pkgs"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install $APTARGS --no-install-recommends $pkgs
    fi
}

pkg_deb_chk() {
    dpkg -s ${1:?} 2>/dev/null | grep -q "^Status: install ok installed";
}

cmd_pip() {
    echo "Installing necessary packages from pip3"
    pip3 install --user -r requirements.txt
}

cmd_pipweb() {
    echo "Installing necessary packages from pip3 for scion-web"
    pip3 install --user -r sub/web/requirements.txt
}

cmd_zlog() {
    pkg_deb_chk zlog && return
    [ -f /usr/lib/libzlog.so ] && return
    local tmpdir=$(mktemp -d /tmp/zlog.XXXXXXX)
    curl -L https://github.com/HardySimpson/zlog/archive/1.2.12.tar.gz | tar xzf - --strip-components=1 -C $tmpdir
    (
        cd $tmpdir
        make -j6
        echo "ldconfig" >> postinstall-pak
        echo "ldconfig" >> postremove-pak
        sudo checkinstall -D --pkgname zlog --nodoc -y --deldoc --deldesc --strip=no --stripso=no --pkgversion 1.2.12
        sudo rm *deb
    )
    rm -r "${tmpdir:?}"
}

cmd_golang() {
    echo "Checking for go 1.6"
    if ! chk_go; then
        echo "Installing golang-1.6 from apt"
        # Include git, as it's needed for fetching go deps. Relevant for
        # testing building Go code inside docker.
        sudo DEBIAN_FRONTEND=noninteractive apt-get install $APTARGS --no-install-recommends golang-1.6 git
    fi
    echo "Installing go tools"
    go get -v $(tools/godeps.py)
    echo "Installing managed go dependencies (via trash)"
    trash -C go
    echo "Installing go dependencies"
    go get -v $(<go/deps.txt)
    echo "Copying go-capnproto2's go.capnp into proto/"
    local srcdir=$(go list -f "{{.Dir}}" zombiezen.com/go/capnproto2)
    cp ${srcdir:?}/std/go.capnp proto/go.capnp
}

chk_go() {
    type -P go &>/dev/null && go version | grep -Eq ' (go1.6|go1.7)'
}

cmd_misc() {
    echo "Installing supervisor packages from pip2"
    pip2 install --user supervisor==3.1.3
    pip2 install --user supervisor-quick
}

cmd_help() {
	cat <<-_EOF
	$PROGRAM CMD
	
	Usage:
	    $PROGRAM all
	        Install all dependencies (recommended).
	    $PROGRAM pkgs
	        Install all system package dependencies (e.g. via apt-get).
	        Uses sudo.
	    $PROGRAM pip
	        Install all pip package dependencies (using --user, so no root
	        access required)
	    $PROGRAM pipweb
	        Install all pip package dependencies of scion-web (using --user, so
	        no root access required)
	    $PROGRAM zlog
	        Install libzlog
	    $PROGRAM golang
	        Install golang-1.6
	    $PROGRAM misc
	        Install any additional packages not from the first 2 sources.
	    $PROGRAM help
	        Show this text.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift || { cmd_help; exit; }

case "$COMMAND" in
    all|pkgs|pip|pipweb|golang|zlog|misc)
            "cmd_$COMMAND" "$@" ;;
    help)  cmd_help ;;
    *)  cmd_help; exit 1 ;;
esac
