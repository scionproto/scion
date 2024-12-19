#!/bin/bash

set -euo pipefail

set -x
if [ -n ${SCION_DEB_PACKAGES+x} ]; then
    # Invocation from bazel:
    # SCION_DEB_PACKAGES is a space-separated list of filenames of (symlinks to) .deb packages.
    # Below we mount this stuff into a docker container, which won't work with symlinks.
    # Copy everything into a tmp directory.
    tmpdir="${TEST_TMPDIR?}"
    cp ${SCION_DEB_PACKAGES} "${tmpdir}"
    SCION_DEB_PACKAGES_DIR=$(realpath ${tmpdir})
else
    SCION_ROOT=$(realpath $(dirname $0)/../../)
    SCION_DEB_PACKAGES_DIR=${SCION_DEB_PACKAGES_DIR:-${SCION_ROOT}/deb}
fi
DEBUG=${DEBUG:-0}
set +x

function cleanup {
    docker container rm -f debian-systemd || true
    docker image rm --no-prune debian-systemd || true
}
cleanup

if [ "$DEBUG" == 0 ]; then  # if DEBUG: keep container debian-systemd running after test
    trap cleanup EXIT
fi

# Note: specify absolute path to Dockerfile because docker will not follow bazel's symlinks.
# Luckily we don't need anything else in this directory.
docker build -t debian-systemd -f $(realpath dist/test/Dockerfile) dist/test

# Start container with systemd in PID 1.
# Note: there are ways to avoid --privileged, but its unreliable and appears to depend on the host system
docker run -d --rm --name debian-systemd -t \
    --tmpfs /tmp \
    --tmpfs /run \
    --tmpfs /run/lock \
    --tmpfs /run/shm \
    -v $SCION_DEB_PACKAGES_DIR:/deb \
    --privileged \
    debian-systemd:latest

docker exec -i debian-systemd /bin/bash <<'EOF'
    set -xeuo pipefail
    arch=$(dpkg --print-architecture)

    # check that the deb files are all here (avoid cryptic error from apt-get)
    stat /deb/scion-{router,control,dispatcher,daemon,ip-gateway,tools}_*_${arch}.deb > /dev/null

    # router
    apt-get install /deb/scion-router_*_${arch}.deb
    cat > /etc/scion/br-1.toml <<INNER_EOF
        [general]
        id = "br-1"
        config_dir = "/etc/scion"
INNER_EOF
    cat > /etc/scion/topology.json <<INNER_EOF
        {
            "isd_as": "1-ff00:0:a",
            "mtu": 1472,
            "dispatched_ports": "1024-65535",
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
    mkdir /etc/scion/keys
    echo -n 0123456789abcdef | base64 | tee /etc/scion/keys/master{0,1}.key
    systemctl enable --now scion-router@br-1.service
    sleep 1
    systemctl status scion-router@br-1.service

    # dispatcher
    apt-get install /deb/scion-dispatcher_*_${arch}.deb
    systemctl enable --now scion-dispatcher.service
    sleep 1
    systemctl status scion-dispatcher.service
    systemctl stop scion-dispatcher.service

    # tools
    # Install first so we can directly use them to generate some testcrypto
    # This has a depency on the daemon package
    apt-get install /deb/scion-tools_*_${arch}.deb /deb/scion-daemon_*_${arch}.deb
    pushd /tmp/
    scion-pki testcrypto --topo <(cat << INNER_EOF
ASes:
    "1-ff00:0:1": {core: true, voting: true, issuing: true, authoritative: true}
    "1-ff00:0:a": {cert_issuer: "1-ff00:0:1"}
INNER_EOF
    )
    cp -r gen/ASff00_0_a/* /etc/scion/
    cp gen/ISD1/trcs/* /etc/scion/certs/
    popd
    # ... (to be continued)

    # control
    apt-get install /deb/scion-control*_${arch}.deb
    cat > /etc/scion/cs-1.toml << INNER_EOF
        general.id = "cs-1"
        general.config_dir = "/etc/scion"
        trust_db.connection = "/var/lib/scion/cs-1.trust.db"
        beacon_db.connection = "/var/lib/scion/cs-1.beacon.db"
        path_db.connection = "/var/lib/scion/cs-1.path.db"
INNER_EOF
    systemctl enable --now scion-control@cs-1.service
    sleep 1
    systemctl status scion-control@cs-1.service
    systemctl is-active scion-dispatcher.service  # should be re-started as dependency
    systemctl stop scion-control@cs-1.service scion-dispatcher.service

    # daemon
    systemctl enable --now scion-daemon.service
    systemctl status scion-daemon.service
    sleep 1
    systemctl is-active scion-dispatcher.service  # should be re-started as dependency
    # ... tools (continued)
    #     now with the daemon running, we can test `scion` e.g. to inspect our local SCION address
    scion address
    systemctl stop scion-daemon.service scion-dispatcher.service

    # scion-ip-gateway
    apt-get install /deb/scion-ip-gateway_*_${arch}.deb
    systemctl start scion-ip-gateway.service
    sleep 1
    # Note: this starts even if the default sig.json is not a valid configuration
    systemctl status scion-ip-gateway.service
    systemctl is-active scion-dispatcher.service scion-daemon.service # should be re-started as dependency
    # Note: the gateway will only create a tunnel device once a session with a
    # neighbor is up. This is too complicated to arrange in this test. Instead,
    # we just ensure that the process has the required capabilities to do so.
    getpcaps $(pidof scion-ip-gateway) | tee /dev/stderr | grep -q "cap_net_admin" || echo "missing capability 'cap_net_admin'"

    echo "Success!"
EOF
