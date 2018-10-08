# SCION Environments

There are different ways SCION services can be run. The different enviroments are

-   development (local)
-   testing (local and CI)
-   production

And the different service backends are

-   supervisor
-   docker

In the following we assume the default topology is being run.

## Development with supervisor

All services run native on the host, controlled by supervisor. In this case one dispatcher is run on
loopback. There is one SCIOND per AS, the sockets can be found in `/run/shm/<dispatcher|sciond>`.
One zookeeper instance is run on the host.

## Development with docker

Docker-compose is used to run every service in its own container (including zookeeper). There is one
dispatcher, one SCIOND per AS.

[//]: # "We run one dispatcher and one SCIOND per AS, their sockets are shared to the infra
services using docker volumes. Each AS has its own docker network."

## Testing with supervisor and docker (CI and `./tools/ci/local`)

In this case the services are run by supervisor inside a testing container (scion_ci). This case has
the same properties as [Development with supervisor] inside a container. A normal zookeeper instance
is run in the container.

## Testing with docker only (Currently not supported for the CI environment)

For testing without effects on the usual `gen` directory, it is possible to create a temporary
directory and generate the topology in there. E.g.
`DOCKER_ARGS="--entrypoint= " HOME_DIR=/tmp/scion ./docker.sh run bash -c "./scion.sh topology -d"`
will put the topology files in `/tmp/scion/gen`. Use
`DOCKER_ARGS="--entrypoint= " HOME_DIR=/tmp/scion ./docker.sh run bash -c "./scion.sh start"` to run
this topology.

- You can also run integration tests using `docker.sh`
- Make sure the host zookeeper instance is stopped
- Make sure you do not create a topology in an already used tmp folder

## Production

In production one would run **one** dispatcher and any number of border routers and infra services
per host.
