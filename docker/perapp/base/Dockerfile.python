FROM scion:latest
USER root
WORKDIR /root/scion-docker
COPY copy_package .
# Prepare generic python libraries
RUN ./copy_package python3.5-minimal '/usr/share'
RUN ./copy_package libpython3.5-minimal '/usr/share'
RUN ./copy_package libpython3.5-stdlib '/usr/share'
RUN ./copy_package libexpat1 '/usr/share'
RUN ./copy_package zlib1g '/usr/share'
RUN ln -s /usr/bin/python3.5 /rootfs/usr/bin/python3
# Prepare our python libraries
RUN ./copy_package libcapnp-0.5.3 '/usr/share'
RUN ./copy_package libstdc++6 '/usr/share'
RUN ./copy_package libgcc1 '/usr/share'
RUN ./copy_package capnproto '/usr/share'
RUN ./copy_package liblz4-1 '/usr/share'
RUN ./copy_package libsodium18 '/usr/share'
RUN ./copy_package libssl1.0.0 '/usr/share'
RUN ./copy_package python3-lz4 '/usr/share'
RUN ./copy_package python3-pygments '/usr/share'
RUN ./copy_package python3-yaml '/usr/share'
RUN ./copy_package python3-nacl '/usr/share'
RUN ./copy_package python3-kazoo '/usr/share'

FROM scion_app_base:latest
# Copy source code and protos
COPY --from=0 /home/scion/go/src/github.com/scionproto/scion/python /app/
COPY --from=0 /home/scion/go/src/github.com/scionproto/scion/proto /app/proto
# Copy pip packages
COPY --from=0 /home/scion/.local/lib/python3.5/site-packages /usr/lib/python3.5
COPY --from=0 /home/scion/go/src/github.com/scionproto/scion/env/pip3/licenses /LICENSES/pip
COPY --from=0 /home/scion/go/src/github.com/scionproto/scion/env/pip3/requirements.txt /LICENSES/pip/
# Copy prepared python binaries
COPY --from=0 /rootfs /

ENV PYTHONPATH=/app/
