import json
import os


class StaticInfoFromTopoFile:
    fname = "staticInfoConfig.json"

    def __init__(self, args):
        self.args = args

    def generate(self, topo_dicts):
        for topoInfo, topo in topo_dicts.items():
            # Extract staticInfo conf
            info = topo["static info"]
            if info:
                # Save into staticInfoConfig.json
                base_path = topoInfo.base_dir(self.args.output_dir)
                with open(os.path.join(base_path, StaticInfoFromTopoFile.fname), "w") as f:
                    json.dump(info, f, indent=4)
