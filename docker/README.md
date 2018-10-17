# SCION Docker testing image

This directory, along with the top-level docker.sh script and Dockerfile, provide a hermetic build
and test environment for SCION.

The docker image is a basic ubuntu environment, with your git working tree, and all scion
dependencies installed. A full build from scratch will take 5-10mins on a fast machine with a
decent net connection. Subsequent rebuilds are much faster; if you haven't changed `env/`, a
rebuild takes <= 15s.

Before you start, make sure you have Docker installed. Please follow the instructions for
[docker-ce](https://docs.docker.com/install/linux/docker-ce/ubuntu/) and
[docker-compose](https://docs.docker.com/compose/install/).

The `scion_base` docker image contains all the dependencies of scion, and so it needs to be
regenerated any time the dependencies change. It is built via:

    ./docker.sh base

The `scion` docker image contains a snapshot of your working tree, and is layered on top of the
`scion_base` image (and hence should be rebuilt if `scion_base` changes). It is built via:

    ./docker.sh build

To run the `scion` docker image:

    ./docker.sh run

This will drop you into a bash shell, in a stripped down ubuntu environment. Your current working
tree has been copied into the image **at build time**. First build and create a topology
`make -s; ./scion.sh topology`, then you can use `./scion.sh run` to start the SCION processes.

If you would like to execute commands from the outside of the container, use

    ./docker.sh start
    ./docker.sh exec CMD
    ./docker.sh stop

`./docker.sh` `run` and `start` will mount the `gen`, `logs` and `gen-certs` directories from a
temp directory. You can pass your own directory with `SCION_MOUNT`.

    SCION_MOUNT=/tmp/scion_out ./docker.sh run "./scion.sh"

or

    SCION_MOUNT=/tmp/scion_out ./docker.sh start
    ./docker.sh exec ./scion.sh topology -d
    ./docker.sh exec ./integration/integration_test.sh
    ./docker.sh stop`

Make sure you collect any relevant data from the container before running `./docker.sh stop` as
this stops and removes the container. The temp directory will still be available.

See `./docker.sh help` for further commands/usage.

## Notes:

-   As `docker.sh` copies your _working tree_, if you're trying to test a commit before sending for
    review/etc, make sure your working directory is clean before building the image. Any new files
    must be at least added to git, even if you haven't committed them, otherwise docker.sh will
    skip them.
-   When running `./scion.sh topology -d` in a container, make sure the zookeeper instance on your
    host is stopped.
