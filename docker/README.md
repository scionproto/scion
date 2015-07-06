SCION Docker testing image
==========================

This directory, along with the top-level docker.sh script, provide a hermetic
build and test environment for SCION.

There are docker image is a basic ubuntu environment, with your working tree,
and all scion dependancies installed, and all SCION setup steps done (i.e.
`./scion.sh init topology setup`). A full build from scratch will take 5-10mins
on a fast machine with a decent net connection.  Subsequent rebuilds are Much
faster; if you haven't changed scion.sh or the dependancy list, a rebuild takes
<= 15s.

Before you start, make sure you have Docker installed. On debian-based systems:

    sudo apt-get install docker.io

To build the docker image:

    ./docker.sh build

To run the docker image:

    ./docker.sh run

This will drop you into a bash shell, in a stripped down ubuntu environment.
Your current working tree has been copied into the image **at build time**, and is
available at `~/scion.git`. You can now use `./scion.sh run` to start the SCION
processes.

See `./docker.sh help` for further commands/usage.

Notes:
------
 * As `docker.sh` copies your *working tree*, if you're trying to test a commit
   before sending for review/etc, make sure your working directory is clean
   before building the image.
 * Currently there is no way to view generated output (like code coverage, or
   sphinx-docs) outside of the image.
