SCION Topology Generator
========================

Necessary steps to use the topology generator

1. [BRITE](http://www.cs.bu.edu/brite/) should be downloaded. Using the BRITE output, we convert it into a SCION topology. BRITE can be downloaded from this [link](http://www.cs.bu.edu/brite/download.html)

2. There are a couple of ways to generate a BRITE output file.

	a) Using GUI provided

	b) Command line interface using BRITE Java source code.

	To quickly generate a brite output file using the second method,

		a) Go to BRITE/Java

		b) To install BRITE, type `make all`

		c) To generate a new topology, type 'java Main.Brite {conf_file} {output_file} seed_file'. This generates `{output_file}.brite`. 

3. Many conf_files are provided in `BRITE/conf` directory. But for our purposes you can use `topology/brite/ASBarabasi_SCION.conf`. To configure the number of nodes you want and other parameters, one can easily modify the conf file. Here, we are using the [Barabasi model](http://en.wikipedia.org/wiki/Barab%C3%A1si%E2%80%93Albert_model) to generate the AS topology.

4. After brite output files are generated, run the `topology/brite/topology_generator.py`. This will create `ADConfigurations.json`. Each brite file will be converted into an ISD and all the ISD's are interconnected using min, max degrees which can be specified using -c switch.

5. The -o switch can be used to generate a dot output file. But this does not work with python3. It only works with python2. Install pygraphviz using pip2 to use this switch.

6. Packages necessary for using Topology Generator: networkx, argparse. Additionally one can also install pygraphviz to generate a dot output file.

All command options for running topology_generator.py

	a) -f (or) --file: Give all brite files seperately one after another

	b) -d (or) --dir: Convert all files in the specified directory. Each of the file is converted into an ISD, then core AD's in these ISD's are connected

	c) -c (or) --degree: Two arguments to be given - min and max degrees for connections between core AD's. It is used for generating inter-ISD connections

	d) -o (or) --output: Generate a dot output file