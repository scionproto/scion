FROM scion:latest
COPY bazelrc.quiet ~/.bazelrc
RUN make -s GOGEN_SKIP=1 all setcap && bazel clean
