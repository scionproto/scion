FROM ubuntu:16.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y libcap2-bin iputils-ping iproute2 && apt-get clean

WORKDIR /share
COPY sig.sh .
RUN chmod +x sig.sh
# Install su-exec
ARG SU_EXEC_COMMIT=537b381606f9e455469a355b2de51ce49cd33973
RUN set -e; mkdir su-exec; \
    curl -sSL https://github.com/anapaya/su-exec/archive/${SU_EXEC_COMMIT}.tar.gz | tar xz -C su-exec --strip-components=1; \
    make -C su-exec; mkdir -p /rootfs/sbin; mv su-exec/su-exec /rootfs/sbin/; \
    mkdir -p /rootfs/LICENSES/su-exec; cp su-exec/LICENSE /rootfs/LICENSES/su-exec/LICENSE; \
    rm -r su-exec;
COPY --from=scion_app_builder:latest /home/scion/go/src/github.com/scionproto/scion/bin/sig /app/
RUN ["setcap", "cap_net_admin+ei", "/app/sig"]
# Note: this process needs explicit CAP_NET_ADMIN from docker. e.g. with `cap_add: NET_ADMIN` from docker-compose
ENTRYPOINT ["./sig.sh"]
