#!/bin/bash

cmd_all() {
    cmd_pkgs
    cmd_pip
    cmd_supervisor
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


cmd_supervisor() {
    echo "Installing supervisor packages from pip2"
    pip2 install --user supervisor==3.1.3
    pip2 install --user supervisor-quick
}

cmd_help() {
	cat <<-_EOF
	$PROGRAM [all|pkgs|pip|supervisor|help]
	
	Usage:
	    $PROGRAM all
	        Install all dependancies (recommended).
	    $PROGRAM pkgs
	        Install only system package dependancies via apt-get (uses sudo).
	    $PROGRAM pip
	        Install only pip package dependancies (using --user, root
	        privileges not required).
	    $PROGRAM supervisor
	        Install only supervisor packages (using --user, root privileges
	        not required).
	    $PROGRAM help
	        Show this text.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    all|pkgs|pip|supervisor|help)
        "cmd_$COMMAND" "$@" ;;
    *)
        cmd_help ;;
esac
