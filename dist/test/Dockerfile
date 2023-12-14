FROM debian:12-slim

# Force debconf (called by apt-get) to be noninteractive
ENV DEBIAN_FRONTEND=noninteractive
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN apt-get update && apt-get install --assume-yes systemd libcap2-bin

ENV container docker

# Only "boot" a minimal system with journald and nothing else
CMD ["/bin/systemd", "--unit", "systemd-journald.socket"]
