FROM scion_base:latest
ARG SCION_UID
ARG SCION_GID
ARG DOCKER_GID
ARG GIT_VERSION
ARG GIT_TAG

ENV GIT_VERSION=${GIT_VERSION}
ENV GIT_TAG=${GIT_TAG}

# Make sure the scion user has the same UID/GID as the user on the host
USER root
RUN usermod -u ${SCION_UID:?} scion
RUN groupmod -g ${SCION_GID:?} scion
# Make sure the docker group has the same GID as the group on the host
RUN groupmod -g ${DOCKER_GID:?} docker
RUN chown -R scion: ~scion

USER scion
# Now copy over the current branch
COPY --chown=scion:scion . $BASE/

# Restore the go dependency cache from scion_base
RUN tar xf ~/go_vendor.tar.gz -C go/vendor/

# Restore the python dependency cache from scion_base
RUN tar xf ~/python_local.tar.gz -C ~

# Make sure dependencies haven't been changed since scion_base was rebuilt
RUN docker/deps_check

# Syncing should be a no-op, just need installation to run
RUN make -sC go deps
