FROM ubuntu:16.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y libcap2-bin iputils-ping iproute2 && apt-get clean

WORKDIR /share
COPY sig.sh .
RUN chmod +x sig.sh
COPY --from=scion_app_base:latest /sbin/su-exec /sbin/su-exec
COPY --from=scion_app_builder:latest /home/scion/go/src/github.com/scionproto/scion/bin/sig /app/
RUN ["setcap", "cap_net_admin+ei", "/app/sig"]
# Note: this process needs explicit CAP_NET_ADMIN from docker. e.g. with `cap_add: NET_ADMIN` from docker-compose
ENTRYPOINT ["./sig.sh"]
