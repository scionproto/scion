FROM scion:latest
RUN make -s all setcap && bazel clean
