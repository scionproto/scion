SCION
=====

Python implementation of [SCION](http://www.netsec.ethz.ch/research/SCION), a future Internet architecture.

* [doc](https://github.com/netsec-ethz/scion/tree/master/doc) contains documentation and material to present SCION
* [infrastructure](https://github.com/netsec-ethz/scion/tree/master/infrastructure)
* [lib](https://github.com/netsec-ethz/scion/tree/master/lib) contains the most relevant SCION libraries
* [topology](https://github.com/netsec-ethz/scion/tree/servers/topology) contains the scripts to generate the SCION configuration and topology files, as well as the certificates and ROT files

Necessary steps in order to run SCION:

0. Install required packages with dependencies:

    sudo apt-get install python3 python-dev python3-dev python3-pip screen
    sudo pip3 install bitstring python-pytun pydblite

1. Compile the crypto library:

	./scion.sh init

2. Create the topology and configuration files (according to “topology/ADConfigurations.json”):

	./scion.sh topology

	The resulting directories structuries and files naming will be:

	./topology/ISDX/

>	certificates/ISD:X-AD:Y-V:Z.crt

>	configurations/ISD:X-AD:Y-V:Z.conf

>	encryption_keys/ISD:X-AD:Y-V:Z.key

>	run/ISD:X-AD:Y.sh

>	setup/ISD:X-AD:Y.sh

>	signature_keys/ISD:X-AD:Y-V:Z.key

>	topologies/ISD:X-AD:Y-V:Z.json

>	ISD:X-V:Z.crt (TRC file)

3. Configure the loopback interface accordingly:

 	./scion.sh setup

4. Run the infrastructure

	./scion.sh run

5. Stop the infrastructure

	./scion.sh stop

6. Flush all IP addresses assigned to the loopback interface

	./scion.sh clean

In order to run the unit tests:

0. cd test/

1. PYTHONPATH=../ python3 *_test.py (arguments)

Notes about “topology/ADConfigurations.json”:

* default_subnet (optional): subnet used if one is not defined at the AD level.

* subnet (optional): subnet used for a specific AD (overrides default_subnet).

* level: can either be CORE, INTERMEDIATE, or LEAF.

* beacon_servers, certificate_servers, path_servers (all optional): number of such servers in a specific AD (override the default value 1).

* links: keys are ISD_ID-AD_ID (format also used for the keys of the JSON file itself) and values can either be PARENT, CHILD, PEER, or ROUTING.
