#!/bin/bash

set -e

cmd_all() {
    cmd_pkgs
    cmd_pip
    cmd_zlog
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
        if ! dpkg-query -W --showformat='${Status}\n' $pkg 2> /dev/null | \
            grep -q "install ok installed"; then
            pkgs+="$pkg "
        fi
    done
    if [ -n "$pkgs" ]; then
        echo "Installing missing necessary packages: $pkgs"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install $APTARGS --no-install-recommends $pkgs
    fi
}

cmd_pip() {
    echo "Installing necessary packages from pip3"
    pip3 install --user -r requirements.txt
}

cmd_zlog() {
    ZLOG_DIR=~/.local/lib/zlog
    if [ ! -d $ZLOG_DIR ]; then
        echo "No libzlog directory, download and extract"
        mkdir -p $ZLOG_DIR
        curl -L https://github.com/HardySimpson/zlog/archive/latest-stable.tar.gz | tar xzf - --strip-components=1 -C $ZLOG_DIR
    fi
    if [ ! -e $ZLOG_DIR/src/libzlog.a ]; then
        echo "Libzlog not built yet, building now"
        make -C $ZLOG_DIR
    fi
}

cmd_capnp() {
    if type -P capnp &>/dev/null; then
        return
    fi
    CP_DIR=~/.local/capnproto
    if [ ! -d $CP_DIR ]; then
        echo "No capnproto directory, download and extract"
        mkdir -p $CP_DIR
        curl -L https://capnproto.org/capnproto-c++-0.5.3.tar.gz | tar xzf - --strip-components=1 -C $CP_DIR
    fi
    cd "$CP_DIR"
    ./configure
    make -j6 check
    sudo make install
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
    all|pkgs|pip|capnp|zlog|misc)
            "cmd_$COMMAND" "$@" ;;
    help|*)  cmd_help ;;
esac
