FROM scion:latest
COPY bazelrc.quiet ~/.bazelrc
RUN make -s all setcap GOGEN_SKIP=1 && bazel clean
