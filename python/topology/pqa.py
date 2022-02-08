import os

import yaml


class PqaGenerator:
    fname = "pqa.yml"
    def __init__(self, args):
        self.args = args

    def generate(self, topo_dicts):
        for topoInfo, topo in topo_dicts.items():
            # Extract pqa info
            pqa = topo["pqa"]

            # Save into pqa.yml
            base_path = topoInfo.base_dir(self.args.output_dir)
            with open(os.path.join(base_path, PqaGenerator.fname), "w") as f:
                yaml.dump(pqa, f, indent=4)
