FROM scion:latest

RUN sudo DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y strace

RUN make -s
