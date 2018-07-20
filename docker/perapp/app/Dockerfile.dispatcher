FROM scion_app_base:latest
ENV ZLOG_CFG /share/conf/dispatcher.zlog.conf
COPY --from=scion_app_builder:latest /home/scion/go/src/github.com/scionproto/scion/bin/dispatcher /app/
ENTRYPOINT ["/sbin/su-exec", "/app/dispatcher"]
