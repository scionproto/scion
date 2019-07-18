FROM alpine:3.10

RUN apk update && \
    apk add --no-cache ruby ruby-json && \
    gem install --no-rdoc --no-ri mdl

RUN mkdir /data

WORKDIR /data

ENTRYPOINT ["mdl"]
CMD ["--help"]
