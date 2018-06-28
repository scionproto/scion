FROM scion:latest
USER root
WORKDIR /root/scion-docker
RUN DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y strace
COPY copy_package .
RUN ./copy_package strace '/usr/share'
ARG TOYBOX_VERSION=0.7.7
ARG TOYBOX_SHA=62126936d400d6814c20ffe6153c5827397126b6df7cd81f54e18e7ac34a2d9f
RUN set -ex; \
    cd /rootfs; \
    mkdir bin; \
    curl -SL "https://landley.net/toybox/downloads/binaries/${TOYBOX_VERSION}/toybox-x86_64" > bin/toybox; \
    echo "${TOYBOX_SHA} bin/toybox" | sha256sum -c -; \
    chmod +x bin/toybox; \
    for i in $(bin/toybox --long); do mkdir -p "$(dirname "$i")"; ln -s /bin/toybox $i; done
# Download LICENSE
RUN set -ex; \
    curl -sSL "https://github.com/landley/toybox/blob/${TOYBOX_VERSION}/LICENSE" --create-dirs -o /rootfs/LICENSES/toybox/LICENSE

# Copy strace and toybox
FROM scratch
COPY --from=0 /rootfs /
