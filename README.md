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

1. Make sure that `~/.local/bin` can be found in your `$PATH` variable. For
   example, do the following to update `$PATH` in your `~/.profile` and apply
   the changes to your session:

    `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile && source
    ~/.profile`

1. Install required packages with dependencies:

    `./deps.sh all`

1. Configure the host Zookeeper instance. At a minimum, add `maxClientCnxns=0`
   to `/etc/zookeeper/conf/zoo.cfg`, but replacing it with `docker/zoo.cfg` is
   recommended. This has the standard parameters set, as well as using a ram
   disk for the data log, which greatly improves ZK performance (at the cost of
   reliability, so it should only be done in a testing environment).

1. Create the topology and configuration files (according to
   `topology/ADConfigurations.json`):

    `./scion.sh topology`

    The resulting directory structure will be created:

        ./gen/ISDX/
            certificates/ADY/ISDX-ADY-VZ.crt
            configurations/ISDX-ADY.conf
            encryption_keys/ISDX-ADY.key
            path_policies/ISDX-ADY.json
            signature_keys/ISDX-ADY.key
            supervisor/ISDX-ADY.conf
            topologies/ISDX-ADY.json
            zookeeper/ISDX-ADY/

1. Run the infrastructure:

    `./scion.sh run`

1. Stop the infrastructure:

    `./scion.sh stop`

Notes about `topology/ADConfigurations.json`:

* `defaults.subnet` (optional): override the default subnet of `127.0.0.0/8`.

* `level`: can either be `CORE`, `INTERMEDIATE`, or `LEAF`.

* `beacon_servers`, `certificate_servers`, `path_servers`, `dns_servers` (all
  optional): number of such servers in a specific AD (override the default
  value 1).

* `links`: keys are `ISD_ID-AD_ID` (format also used for the keys of the JSON
  file itself) and values can either be `PARENT`, `CHILD`, `PEER`, or
  `ROUTING`.

## Tests

In order to run the unit tests:

  `./scion.sh test`

