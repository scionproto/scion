#!/bin/bash

set -euo pipefail

set -x
if [ -n ${SCION_OPENWRT_PACKAGES+x} ]; then
    # Invocation from bazel:
    # SCION_DEB_PACKAGES is a space-separated list of filenames of (symlinks to) .deb packages.
    # Below we mount this stuff into a docker container, which won't work with symlinks.
    # Copy everything into a tmp directory.
    tmpdir="${TEST_TMPDIR?}"
    cp ${SCION_OPENWRT_PACKAGES} "${tmpdir}"
    SCION_OPENWRT_PACKAGES_DIR=$(realpath ${tmpdir})
else
    SCION_ROOT=$(realpath $(dirname $0)/../../)
    SCION_OPENWRT_PACKAGES_DIR=${SCION_OPENWRT_PACKAGES_DIR:-${SCION_ROOT}/openwrt}
fi
DEBUG=${DEBUG:-0}
set +x

function cleanup {
    docker container rm -f openwrt-x86_64 || true
    docker image rm --no-prune openwrt-x86_64 || true
}
cleanup

if [ "$DEBUG" == 0 ]; then  # if DEBUG: keep container debian-systemd running after test
    trap cleanup EXIT
fi

# Note: specify absolute path to Dockerfile because docker will not follow bazel's symlinks.
# Luckily we don't need anything else in this directory.
# docker build -t debian-systemd -f $(realpath dist/test/Dockerfile) dist/test

# Start container as-is.
docker run -d --rm --name openwrt-x86_64 -t \
       -v $SCION_OPENWRT_PACKAGES_DIR:/openwrt \
       "openwrt/rootfs" /sbin/init

docker exec -i openwrt-x86_64 /bin/ash <<'EOF'
    set -xeuo pipefail
    arch=x86_64

    # give some time to finish booting
    sleep 5

    # Everythign we need is in /openwrt.
    cd /openwrt

    # check that the deb files are all here (avoid cryptic error from apt-get)
    for c in router control dispatcher daemon gateway tools common coremark; do
    	ls /openwrt/scion-${c}_*_${arch}.ipk > /dev/null
    done

    # Install the common package. It's just basic config files.
    opkg install scion-common_*_${arch}.ipk

    # Continue with the easy stuff. Run coremark.
    opkg install scion-coremark_*_${arch}.ipk
    #    /usr/bin/scion-coremark > /tmp/coremark.out
    #	 cat /tmp/coremark.out

    # Now the real stuff...

    # router
    opkg install scion-router_*_${arch}.ipk
    cat > /etc/scion/router.toml <<INNER_EOF
        [general]
        id = "br-1"
        config_dir = "/etc/scion"
INNER_EOF
    cat > /etc/scion/topology.json <<INNER_EOF
        {
            "isd_as": "1-ff00:0:a",
            "mtu": 1472,
            "border_routers": {
                "br-1": {
                    "internal_addr": "127.0.0.1:30001"
                }
            },
            "control_service": {
                "cs-1": {
                    "addr": "127.0.0.1:31002"
                }
            }
        }
INNER_EOF
    # mkdir -p /etc/scion/keys (dummy keys come with the install)
    # echo -n 0123456789abcdef | base64 | tee /etc/scion/keys/master{0,1}.key
    service scion-router enable
    service scion-router start
    sleep 1
    pgrep scion-router >/dev/null 2>&1

    # dispatcher
    opkg install scion-dispatcher_*_${arch}.ipk
    service scion-dispatcher enable
    service scion-dispatcher start
    sleep 1
    pgrep 'scion-dispatcher' >/dev/null 2>&1

    # tools
    # Install first so we can directly use them to generate some testcrypto
    # This has a depency on the daemon package
    opkg install scion-tools_*_${arch}.ipk
    opkg install scion-daemon_*_${arch}.ipk
    cd /tmp
    scion-scion-pki testcrypto --topo <(cat << INNER_EOF
ASes:
    "1-ff00:0:1": {core: true, voting: true, issuing: true, authoritative: true}
    "1-ff00:0:a": {cert_issuer: "1-ff00:0:1"}
INNER_EOF
    )
    cp -r gen/ASff00_0_a/* /etc/scion/
    cp gen/ISD1/trcs/* /etc/scion/certs/
    cd /openwrt
    # ... (to be continued)

    # control
    opkg install scion-control*_${arch}.ipk
    cat > /etc/scion/control.toml << INNER_EOF
        general.id = "cs-1"
        general.config_dir = "/etc/scion"
        trust_db.connection = "/var/lib/scion/cs-1.trust.db"
        beacon_db.connection = "/var/lib/scion/cs-1.beacon.db"
        path_db.connection = "/var/lib/scion/cs-1.path.db"
INNER_EOF
    service scion-control enable
    service scion-control start
    sleep 1
    pgrep 'scion-control' >/dev/null 2>&1
    service scion-control stop

    # daemon
    # service scion-daemon enable
    # service scion-daemon start
    # sleep 3
    # For some reason, this one is already running... TBFO
    pgrep 'scion-daemon' >/dev/null 2>&1

    # (continuing) ... tools 
    # now with the daemon running, we can test `scion` e.g. to inspect our local SCION address
    scion-scion address

    # scion-gateway
    opkg install scion-gateway_*_${arch}.ipk
    service scion-gateway enable
    service scion-gateway start
    sleep 1
    # Note: this starts even if the default sig.json is not a valid configuration
    pgrep 'scion-gateway' >/dev/null 2>&1

    # Note: the gateway will only create a tunnel device once a session with a
    # neighbor is up. This is too complicated to arrange in this test.

    echo "Success!"
EOF
