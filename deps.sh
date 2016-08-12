#!/bin/bash

set -e

cmd_all() {
    cmd_pkgs
    # Must be before cmd_pip, as pycapnp depends on capnp being installed.
    cmd_capnp
    cmd_pip
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

cmd_zlog() {
    pkg_deb_chk zlog && return
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

cmd_capnp() {
    pkg_deb_chk capnp && return
    local tmpdir=$(mktemp -d /tmp/capnp.XXXXXXX)
    curl -L https://capnproto.org/capnproto-c++-0.5.3.tar.gz | tar xzf - --strip-components=1 -C $tmpdir
    (
        cd $tmpdir
        ./configure
        make -j6
        echo "ldconfig" >> postinstall-pak
        echo "ldconfig" >> postremove-pak
        mkdir doc-pak
        cp README.txt LICENSE.txt doc-pak
        sudo checkinstall -D --pkgname capnp --nodoc -y --deldoc --deldesc --strip=no --stripso=no --backup=no --pkgversion 0.5.3
        find -mindepth 1 -delete
    )
    rmdir "${tmpdir:?}"
}

cmd_golang() {
    echo "Checking for go 1.6"
    if ! chk_go; then
        echo "Installing golang-1.6 from apt"
        # Include git, as it's needed for fetching go deps. Relevant for
        # testing building Go code inside docker.
        sudo DEBIAN_FRONTEND=noninteractive apt-get install $APTARGS --no-install-recommends golang-1.6 git
    fi
    echo "Installing go dependencies"
    go get -v $(tools/godeps.py) $(<go/deps.txt)
}

chk_go() {
    type -P go &>/dev/null && go version | grep -q ' go1.6'
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
	    $PROGRAM zlog
	        Install libzlog
	    $PROGRAM capnp
	        Install capnproto
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
    all|pkgs|pip|capnp|golang|zlog|misc)
            "cmd_$COMMAND" "$@" ;;
    help|*)  cmd_help ;;
esac
