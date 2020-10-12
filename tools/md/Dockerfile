FROM alpine:3.10

RUN apk update && \
    apk add --no-cache ruby ruby-json && \
    gem install --no-rdoc --no-ri -v 0.9.0 mdl

RUN mkdir /data

WORKDIR /data

ENTRYPOINT ["mdl"]
CMD ["--help"]
