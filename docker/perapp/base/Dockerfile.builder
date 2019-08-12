FROM scion:latest
RUN make -s GOGEN_SKIP=1 all setcap && bazel clean
