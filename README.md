SCION
=====

An implementation of [SCION](http://www.scion-architecture.net), a future
Internet architecture.

* [docker/](/docker): support files to run SCION inside of Docker
  containers.
* [go/](/go): parts of the implementation that are written in
  [Go](http://golang.org).
  * [border_router](/go/border): Border Router
  * [certificate_server](/go/cert_srv): Certificate Server
  * [scion_ip_gateway](/go/sig): SCION IP Gateway
  * [lib](/go/lib): shared SCION Go libraries
* [python/](/python): the parts of the infrastructure
  implemented in Python.
  * [beacon_server](/python/beacon_server): Beacon Server
  * [certificate_server](/python/cert_server): Certificate Server
  * [path_server](/python/path_server): Path Server
  * [lib/](/python/lib): shared SCION Python libraries
  * [topology](/python/topology): generator for generating a local topology,
    including all the necessary configuration, key, and certificate files
* [proto/](/proto): the protocol definitions for use with [Cap’n
  Proto](https://capnproto.org/).
* [sub/](/sub): the git submodules used by SCION
* [supervisor/](/supervisor): the configuration for
  [supervisord](http://supervisord.org/)
* [tools/](/tools): assorted support tools
* [topology/](/topology): various topology definitions and configurations

Necessary steps in order to run SCION:

1. Make sure that you are using a clean and recently updated **Ubuntu 16.04**.

1. Install [Bazel](https://bazel.build).

1. Make sure that you have a
   [Go workspace](https://golang.org/doc/code.html#GOPATH) setup, and that
   `~/.local/bin`, and `$GOPATH/bin` can be found in your `$PATH` variable. For example:

    ```
    echo 'export GOPATH="$HOME/go"' >> ~/.profile
    echo 'export PATH="$HOME/.local/bin:$GOPATH/bin:$PATH"' >> ~/.profile
    source ~/.profile
    mkdir -p "$GOPATH"
    ```

1. Check out scion into the appropriate directory inside your go workspace (or
   put a symlink into the go workspace to point to your existing scion
   checkout):
   ```
   mkdir -p "$GOPATH/src/github.com/scionproto"
   cd "$GOPATH/src/github.com/scionproto"
   git clone --recursive git@github.com:scionproto/scion
   cd scion
   ```
   If you don't have a github account, or haven't setup ssh access to it, this
   command will make git use https instead:
   `git config --global url.https://github.com/.insteadOf git@github.com:`

1. Install required packages with dependencies:
    ```
    ./env/deps
    ```

1. Install `docker` and `docker-compose`. Please follow the instructions for
   [docker-ce](https://docs.docker.com/install/linux/docker-ce/ubuntu/) and
   [docker-compose](https://docs.docker.com/compose/install/). Add your user to the docker group:
   `sudo usermod -a -G docker $LOGNAME`. Log out and log back in so that your group membership is
   re-evaluated.

1. Create the topology and configuration files (according to
   `topology/Default.topo`):

    `./scion.sh topology`

    The resulting directory structure will be created:

        ./gen/ISD{X}/AS{Y}/
            {elem}{X}-{Y}-{Z}/
                as.yml
                path_policy.yml
                supervisord.conf
                topology.yml
                certs/
                    ISD{X}-AS{Y}-V0.crt
                    ISD{X}-V0.trc
                keys/
                    as-sig.key

   The default topology looks like [this](doc/fig/default_topo.png).

1. Run the infrastructure:

    `./scion.sh run`

1. Stop the infrastructure:

    `./scion.sh stop`

Notes about `topology/Default.topo`:

* `defaults.subnet` (optional): override the default subnet of `127.0.0.0/8`.

* `core` (optional): specify if this is a core AS or not (defaults to 'false').

* `beacon_servers`, `certificate_servers`, `path_servers`, (all optional):
  number of such servers in a specific AS (override the default value 1).

* `links`: keys are `ISD_ID-AS_ID` (format also used for the keys of the JSON
  file itself) and values can either be `PARENT`, `CHILD`, `PEER`, or
  `CORE`.

## Tests

In order to run the unit tests:

  `./scion.sh test`
