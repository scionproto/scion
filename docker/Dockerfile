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
RUN find ~scion -not -user scion -execdir chown scion {} \+

USER scion
# Now copy over the current branch
COPY --chown=scion:scion . $BASE/

# Restore the python dependency cache from scion_base
RUN tar xf /scioncache/python_local.tar.gz -C ~

# Restore the cache of Bazel dependencies
# Bazel creates timestamps 10 years in the future, so let's not warn about that.
RUN tar xf /scioncache/bazel.tar.gz -C ~ --warning=no-timestamp

# Make sure dependencies haven't been changed since scion_base was rebuilt
RUN docker/deps_check
