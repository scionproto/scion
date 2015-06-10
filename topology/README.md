SCION Topology Generator
========================

Necessary steps to use the topology generator

1. BRITE(http://www.cs.bu.edu/brite/) should be downloaded. Using the BRITE output, we convert it into a SCION topology. BRITE can be downloaded from http://www.cs.bu.edu/brite/download.html

2. There are a couple of ways to generate a BRITE output file.

	a) Using GUI provided

	b) Command line interface using BRITE Java source code.

To quickly generate a brite output file using the second method,

	a) Go to BRITE/Java

	b) To install BRITE, type `make all`

	c) To generate a new topology, type 'java Main.Brite {conf_file} {output_file} seed_file'. This generates `{output_file}.brite`. 

3. Many conf_files are provided in `BRITE/conf` directory. But for our purposes you can use `topology/ASBarabasi_SCION.conf`. To configure the number of nodes you want and other parameters, one can easily modify the conf file. Here, we are using the Barabasi model(http://en.wikipedia.org/wiki/Barab%C3%A1si%E2%80%93Albert_model) to generate the AS topology.

4. After a brite output file is generated, run the `topology/topology_generator.py` with the brite output file. This will overwrite the existing `topology/ADConfigurations.json`