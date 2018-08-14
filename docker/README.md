SCION Docker testing image
==========================

This directory, along with the top-level docker.sh script and Dockerfile,
provide a hermetic build and test environment for SCION.

The docker image is a basic ubuntu environment, with your working tree, and all
scion dependencies installed, and all SCION setup steps done (i.e. `./scion.sh
topology`). A full build from scratch will take 5-10mins on a fast machine
with a decent net connection. Subsequent rebuilds are Much faster; if you
haven't changed deps.sh or the dependency list, a rebuild takes <= 15s.

Before you start, make sure you have Docker installed. Please follow the instructions for
[docker-ce](https://docs.docker.com/install/linux/docker-ce/ubuntu/), you may also want to install
[docker-compse](https://docs.docker.com/compose/install/).

The `scion_base` docker image contains all the dependencies of scion, and so it
needs to be regenerated any time the dependencies change. It is built via: 

    ./docker.sh base

The `scion` docker image contains a snapshot of your working tree, and is
layered on top of the `scion_base` image (and hence should be rebuilt if
`scion_base` changes). It is built via:

    ./docker.sh build

To run the `scion` docker image:

    ./docker.sh run

This will drop you into a bash shell, in a stripped down ubuntu environment.
Your current working tree has been copied into the image **at build time**.
You can now use `./scion.sh run` to start the SCION processes.

See `./docker.sh help` for further commands/usage.

Notes:
------
 * As `docker.sh` copies your *working tree*, if you're trying to test a commit
   before sending for review/etc, make sure your working directory is clean
   before building the image. Any new files must be at least added to git,
   even if you haven't committed them, otherwise docker.sh will skip them.
 * The code coverage and sphinx-docs outputs are made available outside the
   container transparently, in the same directories (`htmlcov/` and
   `sphinx-doc/_build`) as external builds use.
