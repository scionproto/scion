# SCION

[![Documentation](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/scionproto/scion)
[![ReadTheDocs](https://img.shields.io/badge/doc-reference-blue?version=latest&style=flat&label=docs&logo=read-the-docs&logoColor=white)](https://anapaya-scion.readthedocs-hosted.com/en/latest)
[![Build Status](https://badge.buildkite.com/e7ca347d947c23883ad7c3a4d091c2df5ae7feb52b238d29a1.svg?branch=master)](https://buildkite.com/scionproto/scion)
[![Go Report Card](https://goreportcard.com/badge/github.com/scionproto/scion)](https://goreportcard.com/report/github.com/scionproto/scion)
[![GitHub issues](https://img.shields.io/github/issues/scionproto/scion/help%20wanted.svg?label=help%20wanted&color=blue)](https://github.com/scionproto/scion/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22)
[![Release](https://img.shields.io/github/release-pre/scionproto/scion.svg)](https://github.com/scionproto/scion/releases)
[![license](https://img.shields.io/github/license/scionproto/scion.svg?maxAge=2592000)](https://github.com/scionproto/scion/blob/master/LICENSE)

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
    * [lib/](/python/lib): shared SCION Python libraries
    * [topology](/python/topology): generator for generating a local topology,
        including all the necessary configuration, key, and certificate files
* [proto/](/proto): the protocol definitions for use with [Cap’n
  Proto](https://capnproto.org/).
* [supervisor/](/supervisor): the configuration for
  [supervisord](http://supervisord.org/)
* [tools/](/tools): assorted support tools
* [topology/](/topology): various topology definitions and configurations

Necessary steps in order to run SCION:

1. Make sure that you are using a clean and recently updated **Ubuntu 16.04**.
   This environment assumes you're running as a non-root user with sudo access.

1. Install [Bazel](https://bazel.build) version 1.2.0:

   ```bash
   sudo apt-get install g++ unzip zip
   wget https://github.com/bazelbuild/bazel/releases/download/1.2.0/bazel-1.2.0-installer-linux-x86_64.sh
   bash ./bazel-1.2.0-installer-linux-x86_64.sh --user
   rm ./bazel-1.2.0-installer-linux-x86_64.sh
   ```

1. Check out scion into the appropriate directory inside your workspace:

   ```bash
   cd "<workspace>"
   git clone https://github.com/scionproto/scion
   cd scion
   ```

1. Install required packages with dependencies:

   ```bash
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

   ```bash
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
   ```

   The default topology looks like [this](doc/fig/default_topo.png).

1. Run the infrastructure:

    `./scion.sh run`

1. Stop the infrastructure:

    `./scion.sh stop`

Notes about `topology/Default.topo`:

* `defaults.subnet` (optional): override the default subnet of `127.0.0.0/8`.

* `core` (optional): specify if this is a core AS or not (defaults to 'false').

* `control_servers` (optional):
  number of such servers in a specific AS (override the default value 1).

* `links`: keys are `ISD_ID-AS_ID` (format also used for the keys of the JSON
  file itself) and values can either be `PARENT`, `CHILD`, `PEER`, or
  `CORE`.

## Tests

In order to run the unit tests:

  `./scion.sh test`
