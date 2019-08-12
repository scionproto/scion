FROM scion:latest
RUN make all setcap && bazel clean
