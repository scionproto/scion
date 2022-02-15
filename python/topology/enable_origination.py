import pathlib
class PqaGenerator:
    fname = "pqa.yml"

    def __init__(self, args):
        self.args = args

    def generate(self, topo_dicts):
        for topoInfo, topo in topo_dicts.items():
            if topo.get("originate", False):
                base_path = topoInfo.base_dir(self.args.output_dir)
                pathlib.Path(base_path, "originate").touch()

