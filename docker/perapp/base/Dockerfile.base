FROM scion:latest
USER root
WORKDIR /root/scion-docker
COPY copy_package .
RUN ./copy_package libc6 '/usr/share'
RUN ./copy_package libcap2 '/usr/share'
RUN ./copy_package libcap2-bin '/usr/share'

# Install su-exec
ARG SU_EXEC_COMMIT=537b381606f9e455469a355b2de51ce49cd33973
RUN set -e; mkdir su-exec; \
    curl -SL https://github.com/anapaya/su-exec/archive/${SU_EXEC_COMMIT}.tar.gz | tar xz -C su-exec --strip-components=1; \
    make -C su-exec; mkdir -p /rootfs/sbin; mv su-exec/su-exec /rootfs/sbin/; \
    mkdir -p /rootfs/LICENSES/su-exec; cp su-exec/LICENSE /rootfs/LICENSES/su-exec/LICENSE; \
    rm -r su-exec;

# Collect go licenses
RUN set -e; mkdir /rootfs/LICENSES/go; \
    find /home/scion/.cache/bazel/_bazel_scion -iregex '.*\(LICENSE\|COPYING\).*' -exec cp --parents '{}' /rootfs/LICENSES/go ';'

RUN mkdir -m 1777 /rootfs/tmp
RUN mkdir -p /rootfs/usr/share/zoneinfo/; cp -L /usr/share/zoneinfo/UTC /rootfs/usr/share/zoneinfo/UTC

# Base image with minimal content
FROM scratch
WORKDIR /share
COPY --from=0 /rootfs /
ENV TZ=UTC
ENTRYPOINT ["/sbin/su-exec"]
