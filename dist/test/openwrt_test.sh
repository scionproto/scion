#!/bin/bash

set -euo pipefail

set -x
if [ -n ${SCION_OPENWRT_PACKAGES+x} ]; then
    # Invocation from bazel:
    # SCION_OPENWRT_PACKAGES is a space-separated list of filenames of (symlinks to) .ipk packages.
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
    docker container rm -f openwrt-x86_64 >/dev/null 2>&1 || true
    docker image rm --no-prune openwrt-x86_64 >/dev/null 2>&1 || true
}
cleanup

if [ "$DEBUG" == 0 ]; then  # if DEBUG: keep container openwrt-x86_64 running after test
    trap cleanup EXIT
fi

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

    # check that the pki files are all here (avoid cryptic error from opk)
    for c in persistdbs testconfig router control dispatcher daemon ip-gateway tools bmtools; do
    	ls /openwrt/scion-${c}_*_${arch}.ipk > /dev/null
    done

    # Start with the easy stuff. Install and run coremark.
    opkg install scion-bmtools_*_${arch}.ipk
    /usr/bin/scion-coremark > /tmp/coremark.out
    cat /tmp/coremark.out

    # Uninstall bmtooling. It contains benchmark-only configs that can get in
    # the way.
    opkg remove scion-bmtools

    # Now the real stuff...

    # Install the persistdbs and testconfig packages. It's just basic config
    # files.
    opkg install scion-persistdbs_*_${arch}.ipk
    opkg install scion-testconfig_*_${arch}.ipk

    # Install the tools and generate the testcrypto certs.
    opkg install scion-tools_*_${arch}.ipk
    cd /tmp
    cat > testcrypto_topo << INNER_EOF
ASes:
    "1-ff00:0:1": {core: true, voting: true, issuing: true, authoritative: true}
    "1-ff00:0:a": {cert_issuer: "1-ff00:0:1"}
INNER_EOF
    scion-pki testcrypto --topo /tmp/testcrypto_topo
    cp -r gen/ASff00_0_a/* /etc/scion/
    cp gen/ISD1/trcs/* /etc/scion/certs/
    cd /openwrt

    # Install and start some of the services.
    opkg install scion-dispatcher_*_${arch}.ipk
    opkg install scion-router_*_${arch}.ipk
    opkg install scion-control*_${arch}.ipk
    opkg install scion-daemon_*_${arch}.ipk
    service scion-dispatcher enable
    service scion-router enable
    service scion-control enable
    service scion-daemon enable

    # Give them some time to start and some time to crash
    sleep 3
    pgrep scion-dispatcher
    pgrep scion-router
    pgrep scion-control
    pgrep scion-daemon

    # ...and now we can test the scion tool by inspecting our local SCION address.
    scion address

    # Check that scion-ip-gateway can install and start
    opkg install scion-ip-gateway_*_${arch}.ipk
    service scion-gateway enable
    sleep 3
    # Note: this starts even if the default sig.json is not a valid configuration
    pgrep scion-gateway || /usr/bin/scion-gateway --config=/etc/scion/gateway.toml

    # Note: the gateway will only create a tunnel device once a session with a
    # neighbor is up. This is too complicated to arrange in this test.

    echo "Success!"
EOF
