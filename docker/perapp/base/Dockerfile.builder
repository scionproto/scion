FROM scion:latest
RUN make -s all setcap GOGEN_SKIP=1 && bazel clean
