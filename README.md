SCION
=====

Python implementation of [SCION](http://www.netsec.ethz.ch/research/SCION), a future Internet architecture.

* [doc](/doc) contains documentation and specification of the SCION implementation
* [infrastructure](/infrastructure) contains the code of the SCION infrastructure elements (servers, routers)
* [lib](/lib) contains the most relevant SCION libraries
* [topology](/topology) contains the scripts to generate the SCION configuration and topology files, as well as the certificates and ROT files

Necessary steps in order to run SCION:

1. Make sure that `~/.local/bin` can be found in your $PATH variable.

	For example, do the following to update $PATH in your `~/.profile` and apply the changes to your session:

	`echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile && source ~/.profile`

2. Install required packages with dependencies:

	`./deps.sh all`

3. Compile the crypto library:

	`./scion.sh init`

4. Create the topology and configuration files (according to `topology/ADConfigurations.json`):

	`./scion.sh topology`

	The resulting directory structure will be created:

		./topology/ISDX/
			certificates/ADY/ISD:X-AD:Y-V:Z.crt
			configurations/ISD:X-AD:Y.conf
			encryption_keys/ISD:X-AD:Y.key
			path_policies/ISD:X-AD:Y.json
			signature_keys/ISD:X-AD:Y.key
			supervisor/ISD:X-AD:Y.conf
			topologies/ISD:X-AD:Y.json
			zookeeper/ISDX-ADY/

5. Run the infrastructure:

	`./scion.sh run`

6. Stop the infrastructure:

	`./scion.sh stop`

Notes about `topology/ADConfigurations.json`:

* default_subnet (optional): subnet used if one is not defined at the AD level.

* subnet (optional): subnet used for a specific AD (overrides default_subnet).

* level: can either be CORE, INTERMEDIATE, or LEAF.

* beacon_servers, certificate_servers, path_servers, dns_servers (all optional): number of such servers in a specific AD (override the default value 1).

* links: keys are ISD_ID-AD_ID (format also used for the keys of the JSON file itself) and values can either be PARENT, CHILD, PEER, or ROUTING.

## Tests

In order to run the unit tests:

  `./scion.sh test`

