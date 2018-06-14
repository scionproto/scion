FROM scion_app_base:latest
COPY --from=scion_app_builder:latest /home/scion/go/src/github.com/scionproto/scion/bin/sig /app/
RUN ["setcap", "cap_net_admin+ei", "/app/sig"]
ENTRYPOINT ["/sbin/su-exec", "/app/sig"]
