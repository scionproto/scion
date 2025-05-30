# syntax = docker/dockerfile:1.3
FROM --platform=$BUILDPLATFORM debian:12-slim

ARG TARGETARCH
ARG SCION_VER=0.12.0
ARG RELEASE="https://github.com/scionproto/scion/releases/download/v${SCION_VER}/scion_${SCION_VER}_deb_${TARGETARCH}.tar.gz"

# Force debconf (called by apt-get) to be non-interactive.
# This prevents interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# Install dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install SCION packages. Eventually, also remove the apt cache files
# stored under /var/lib/apt/lists/ to reduce the image size.
RUN mkdir -p /tmp/scion/ && \
    wget --progress=dot:giga "$RELEASE" -O /tmp/scion/pkgs.tar.gz && \
    tar -xzf /tmp/scion/pkgs.tar.gz -C /tmp/scion/ && \
    ls -l /tmp/scion/ && \
    apt-get install -y --no-install-recommends $(find /tmp/scion -name '*.deb') && \
    rm -rf /tmp/scion /var/lib/apt/lists/*

# Create SCION configuration directories.
RUN mkdir -p \
    /etc/scion/crypto/as \
    /etc/scion/certs \
    /etc/scion/keys \
    /etc/scion/config

COPY br.toml /etc/scion/br.toml
COPY cs.toml /etc/scion/cs.toml

WORKDIR /pki

# Setup PKI.
COPY pki-generation.bash /pki/
RUN chmod +x pki-generation.bash && ./pki-generation.bash

# Persist the generated ISD TRC file.
RUN mv /tmp/tutorial-scion-certs/ISD15-B1-S1.trc /etc/scion/certs/

# Persist the generated files.
RUN mkdir -p /opt/tutorial-pki && mv /tmp/tutorial-scion-certs/* /opt/tutorial-pki/

# Copy the initialization script.
COPY start-scion.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-scion.sh
