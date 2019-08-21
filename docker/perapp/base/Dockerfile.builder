FROM scion:latest
COPY bazelrc.quiet ~/.bazelrc
RUN make -s all setcap && bazel clean
