FROM alpine

ARG port
# Must set env var to make PORT available in CMD
ENV PORT ${port}

RUN apk add --update mini_httpd && rm -rf /var/cache/apk/*

CMD mini_httpd -C /etc/mini_httpd/mini_httpd.conf -D -p ${PORT}
