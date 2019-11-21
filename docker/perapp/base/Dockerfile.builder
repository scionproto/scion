FROM scion:latest
COPY bazelrc.quiet ~/.bazelrc
RUN make -s GODEPS_SKIP=1 GOGEN_SKIP=1 all setcap && bazel clean
