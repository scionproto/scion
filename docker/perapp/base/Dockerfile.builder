FROM scion:latest
RUN make -s all && bazel clean
