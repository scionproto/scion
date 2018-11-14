# SCION Environments

There are different ways SCION services can be run. The different enviroments are

-   development (local)
-   testing (local and CI)
-   production

And the different `scion.sh` backends are

-   supervisor
-   docker

## Development with supervisor

All services run native on the host, controlled by supervisor. In this case one dispatcher is run
on loopback. There is one SCIOND per AS, the sockets can be found in
`/run/shm/<dispatcher|sciond>`. One zookeeper instance is run on the host.

## Development with docker

Docker-compose is used to run every service in its own container (including zookeeper). We run
multiple dispatchers and one SCIOND per AS. One dispatcher and the SCIOND share their sockets with
the infra services using docker volumes. And there is one dispatcher per BR, which it shares its
socket with. Each AS has its own docker network and every BR to BR link is a docker network.

## Testing with supervisor and docker (CI and `./tools/ci/local`)

In this case the services are run by supervisor inside a testing container (scion_ci). This case
has the same properties as "Development with supervisor" except it is run inside a container. A
normal zookeeper instance is run in the container.

## Testing with docker only

For testing without effects on the usual `gen` directory, it is possible to create a temporary
directory and generate the topology in there. See `docker/README.md` for more information.

## Production

In production one would run **one** dispatcher and any number of border routers and infra services
per host.
