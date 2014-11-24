SCION
=====

Python implementation of [SCION](http://www.netsec.ethz.ch/research/SCION), a future Internet architecture.

* [doc](https://github.com/netsec-ethz/scion/tree/master/doc) contains documentation and material to present SCION
* [infrastructure](https://github.com/netsec-ethz/scion/tree/master/infrastructure)
* [lib](https://github.com/netsec-ethz/scion/tree/master/lib) contains the most relevant SCION libraries
* [topology](https://github.com/netsec-ethz/scion/tree/servers/topology) contains the scripts to generate the SCION configuration and topology files, as well as the certificates and ROT files


Necessary steps in order to run SCION:

1) Create the topology and configuration files (according to “topology/ADRelationships” and “topology/ADToISD"):
	./scion.sh topology
2) Configure the loopback interface accordingly:
	./scion.sh setup
3) Run the infrastructure
	./scion.sh run
4) Stop the infrastructure
	./scion.sh stop
5) Flush all IP addresses assigned to the loopback interface
	./scion.sh clean
