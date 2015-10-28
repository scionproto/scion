#!/bin/bash

set -e

MN_DIR=$(dirname $0)
APTARGS="$1"

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
    if [ ! -d ~/.local/pox-carp ]; then
        log "Installing POX (https://github.com/noxrepo/pox) to ~/.local/pox-carp"
        wget -nv -O - https://github.com/noxrepo/pox/archive/carp.tar.gz | tar xzf - -C ~/.local
    fi
    log "Installing POX symlink into ~/.local/bin"
    ln -sf ../pox-carp/pox.py ~/.local/bin/pox
fi
if ! which pox > /dev/null; then
    log "Error: no 'pox' in \$PATH, POX not installed correctly"
    exit 1
fi
