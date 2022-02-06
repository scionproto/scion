import os
import random
import json
import pprint
import yaml

import caida_gen as caida

class PqaGenerator:
    """
    Generates a staticInfoConfig files for every AS in a topology with
    parameters chosen randomly with some more some less sensible
    distributions. Generation of the same ISD-AS for the
    same interfaces will yield the same random values.

    The values generated aren't coherent, in that the value
    for a link/path from one side is likely different for the same path
    from the other side.
    """
    fname = "pqa.yml"
    caida = caida.CaidaGraph()

    def __init__(self, args):
        self.args = args

    def generate(self, topo_dicts):
        for topoInfo, topo in topo_dicts.items():
            # Flatten all interfaces into single dictionary
            intfs = {}
            for router in topo["border_routers"].values():
                intfs.update(router["interfaces"])

            r = random.Random(str(topoInfo))  # ISD-AS is seed

            # Extract pqa info
            pqa = topo["pqa"]

            # Save into pqa.yml
            base_path = topoInfo.base_dir(self.args.output_dir)
            with open(os.path.join(base_path, PqaGenerator.fname), "w") as f:
                yaml.dump(pqa, f, indent=4)
