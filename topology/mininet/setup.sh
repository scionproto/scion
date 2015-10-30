#!/bin/bash

set -e

MN_DIR=$(dirname $0)
APTARGS="$1"
SITE_PKGS=~/.local/lib/python2.7/site-packages
POX_DIR="$SITE_PKGS/pox-carp"
POX_LINK="$SITE_PKGS/pox"

log() {
    echo "=====> $@"
}

log "Checking for necessary debian packages"
for pkg in $(< "$MN_DIR/pkgs_debian.txt"); do
    if ! dpkg-query -W --showformat='${Status}\n' $pkg 2> /dev/null | \
        grep -q "install ok installed"; then
        pkgs+="$pkg "
    fi
done
if [ -n "$pkgs" ]; then
    log "Installing missing necessary packages: $pkgs"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install $APTARGS --no-install-recommends $pkgs
    log "Starting the openvswitch-switch service"
    sudo service openvswitch-switch start
fi

log "Installing any necessary python packages via pip"
pip2 install --user -r "$MN_DIR/requirements.txt"

if ! which pox > /dev/null; then
    if [ ! -d "$POX_DIR" ]; then
        log "Installing POX (https://github.com/noxrepo/pox) to $POX_DIR"
        wget -nv -O - https://github.com/noxrepo/pox/archive/carp.tar.gz | tar xzf - -C "$SITE_PKGS"
        ln -sf pox-carp/pox "$POX_LINK"
    fi
    log "Installing POX symlink into ~/.local/bin"
    ln -sf "$POX_DIR/pox.py" ~/.local/bin/pox
fi
if ! which pox > /dev/null; then
    log "Error: no 'pox' in \$PATH, POX not installed correctly"
    exit 1
fi
if ! python2 -c "import pox" &> /dev/null; then
    log "Error: unable to import 'pox' module in python2"
    exit 1
fi
