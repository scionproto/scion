SCION
=====

Python implementation of [SCION](http://www.scion-architecture.net), a future
Internet architecture.

* [doc/](/doc) contains documentation and specification of the SCION
  implementation
* [infrastructure/](/infrastructure) contains the code of the SCION
  infrastructure elements (servers, routers)
* [lib/](/lib) contains the most relevant SCION libraries
* [topology/](/topology) contains the scripts to generate the SCION
  configuration and topology files, as well as the certificates and ROT files

Necessary steps in order to run SCION:

1. Make sure that you have a
   [Go workspace](https://golang.org/doc/code.html#GOPATH) setup, and that
   `~/.local/bin`, `/usr/lib/go-1.6/bin` and `$GOPATH/bin` can be found in your
   `$PATH` variable. For example:

    ```
    echo 'export GOPATH="$HOME/go"' >> ~/.profile
    echo 'export PATH="$HOME/.local/bin:/usr/lib/go-1.6/bin:$GOPATH/bin:$PATH"' >> ~/.profile
    source ~/.profile
    mkdir -p "$GOPATH"
    ```

1. Check out scion into the appropriate directory inside your go workspace (or
   put a symlink into the go workspace to point to your existing scion
   checkout):
   ```
   mkdir -p "$GOPATH/src/github.com/netsec-ethz"
   cd "$GOPATH/src/github.com/netsec-ethz"
   git clone https://github.com/netsec-ethz/scion
   cd scion
   ```

1. Install required packages with dependencies:
    ```
    ./deps.sh all
    go get -u -t -v ./go/...
    ```

1. Configure the host Zookeeper instance. At a minimum, add `maxClientCnxns=0`
   to `/etc/zookeeper/conf/zoo.cfg`, but replacing it with `docker/zoo.cfg` is
   recommended. This has the standard parameters set, as well as using a ram
   disk for the data log, which greatly improves ZK performance (at the cost of
   reliability, so it should only be done in a testing environment).

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

   The default topology looks like [this](doc/fig/default-topo.pdf).

1. Run the infrastructure:

    `./scion.sh run`

1. Stop the infrastructure:

    `./scion.sh stop`

Notes about `topology/Default.topo`:

* `defaults.subnet` (optional): override the default subnet of `127.0.0.0/8`.

* `core` (optional): specify if this is a core AS or not (defaults to 'false').

* `beacon_servers`, `certificate_servers`, `path_servers`, `dns_servers` (all
  optional): number of such servers in a specific AS (override the default
  value 1).

* `links`: keys are `ISD_ID-AS_ID` (format also used for the keys of the JSON
  file itself) and values can either be `PARENT`, `CHILD`, `PEER`, or
  `ROUTING`.

## Tests

In order to run the unit tests:

  `./scion.sh test`
