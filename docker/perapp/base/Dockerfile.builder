FROM scion:latest
RUN set -e; \
    make -s all; \
    bazel clean
