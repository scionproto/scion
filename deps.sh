#!/bin/bash

set -e

cmd_all() {
    cmd_pkgs
    cmd_pip
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


cmd_misc() {
    echo "Installing supervisor packages from pip2"
    pip2 install --user supervisor==3.1.3
    pip2 install --user supervisor-quick
}

cmd_help() {
	cat <<-_EOF
	$PROGRAM [all|pkgs|pip|misc|help]
	
	Usage:
	    $PROGRAM all
	        Install all dependancies.
	    $PROGRAM pkgs
	        Install all system package dependancies (e.g. via apt-get).
	        Uses sudo.
	    $PROGRAM pip
	        Install all pip package dependancies (using --user, so no root
	        access required)
	    $PROGRAM misc
	        Install any additional packages not from the first 2 sources.
	    $PROGRAM help
	        Show this text.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    all|pkgs|pip|misc)
            "cmd_$COMMAND" "$@" ;;
    help|*)  cmd_help ;;
esac
