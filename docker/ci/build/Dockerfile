FROM ubuntu:16.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
    git make curl ca-certificates openssl g++ unzip zip python3-minimal libpython3-stdlib\
    && apt-get clean

# Bazel uses env python so make sure it is there:
RUN ln -s /usr/bin/python3 /usr/bin/python

WORKDIR /data
VOLUME /data

COPY tools/install_bazel install_bazel
RUN ./install_bazel /usr && rm install_bazel

# make -s GODEPS_SKIP=1 GOGEN_SKIP=1 all setcap && bazel clean
ENTRYPOINT [ "make", "-s", "GODEPS_SKIP=1", "GOGEN_SKIP=1", "all", "setcap", "&&", "bazel clean" ]
