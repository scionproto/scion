FROM scion:latest
# This should eventually become "make -s all-nofetch" but, apparently,
# fetching //:scion and the building //:scion with --fetch=false doesn't
# work. See https://github.com/bazelbuild/bazel/issues/7438
RUN make -s all
