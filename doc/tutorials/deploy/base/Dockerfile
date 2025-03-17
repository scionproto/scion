FROM debian-systemd:1.0

ARG RELEASE="https://github.com/scionproto/scion/releases/download/v0.12.0/scion_0.12.0_deb_amd64.tar.gz"

# Prevent interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies (pin versions where possible).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl wget tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install SCION packages without sudo.
RUN mkdir -p /tmp/scion/ && \
    wget --progress=dot:giga "$RELEASE" -O /tmp/scion/pkgs.tar.gz && \
    tar -xzf /tmp/scion/pkgs.tar.gz -C /tmp/scion/ && \
    ls -l /tmp/scion/ && \
    apt-get install -y --no-install-recommends $(find /tmp/scion -name '*.deb') && \
    rm -rf /tmp/scion /var/lib/apt/lists/*

# Create configuration directories.
RUN mkdir -p \
    /etc/scion/crypto/as \
    /etc/scion/certs \
    /etc/scion/keys \
    /etc/scion/config

COPY br.toml /etc/scion/br.toml
COPY cs.toml /etc/scion/cs.toml

COPY entrypoint.bash /entrypoint.bash
RUN chmod +x /entrypoint.bash

WORKDIR /pki

# Setup PKI.
COPY pki-generation.bash /pki/
RUN chmod +x pki-generation.bash && ./pki-generation.bash

# Persist the generated ISD TRC file.
RUN mv /tmp/tutorial-scion-certs/ISD42-B1-S1.trc /etc/scion/certs/

# Persist the generated files.
RUN mkdir -p /opt/tutorial-pki && mv /tmp/tutorial-scion-certs/* /opt/tutorial-pki/
