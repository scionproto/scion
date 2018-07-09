FROM scion_app_base:latest
COPY --from=scion_app_builder:latest /home/scion/go/src/github.com/scionproto/scion/bin/sig /app/
RUN ["setcap", "cap_net_admin+ei", "/app/sig"]
# Note: this process needs explicit CAP_NET_ADMIN from docker. e.g. with `cap_add: NET_ADMIN` from docker-conmpose
ENTRYPOINT ["/sbin/su-exec", "/app/sig"]
