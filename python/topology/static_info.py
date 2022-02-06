import json
import os
import random

import caida_gen as caida
import yaml


def to_pos_int(x):
    return max(0, int(x))


class StaticInfoGenerator:
    """
    Generates a staticInfoConfig files for every AS in a topology with
    parameters chosen randomly with some more some less sensible
    distributions. Generation of the same ISD-AS for the
    same interfaces will yield the same random values.

    The values generated aren't coherent, in that the value
    for a link/path from one side is likely different for the same path
    from the other side.
    """
    fname = "staticInfoConfig.json"

    def gen_latency(self, r):
        return f"{int(r.lognormvariate(1, 0.8)*60)}ms"

    #gen_latency = lambda r: f"{10}ms"
    def gen_bandwith(self, r):
        return int(r.lognormvariate(1, 0.8)*2000000000)

    def gen_long(self, r):
        return 0

    def gen_lat(self, r):
        return 0

    def gen_addr(self, r):
        return "nowhere"

    def gen_hops(self, r):
        return int(random.uniform(1, 7))

    def gen_linktype(self, r):
        return random.choice(["direct", "multihop", "opennet"])


    def __init__(self, args):
        self.args = args

    def generate(self, topo_dicts):
        for topo_info, topo in topo_dicts.items():
            intfs = [intf for router in topo["border_routers"].values()
                     for intf in router["interfaces"].keys()]
            r = random.Random(str(topo_info))  # ISD-AS is seed
            settings = {
                "Latency": {intf: {
                    "Inter": self.gen_latency(r),
                    "Intra": {
                        intf2: self.gen_latency(r) for intf2 in intfs if intf2 != intf
                    }
                } for intf in intfs},
                "Bandwidth": {intf: {
                    "Inter": self.gen_bandwith(r),
                    "Intra": {
                        intf2: self.gen_bandwith(r) for intf2 in intfs if intf2 != intf
                    }
                } for intf in intfs},
                "Linktype": {intf: self.gen_linktype(r) for intf in intfs},
                "Geo": {intf: {
                    "Latitutde": self.gen_lat(r),
                    "Longitude": self.gen_long(r),
                    "Address": self.gen_addr(r),
                } for intf in intfs},
                "Hops": {intf: {
                    "Intra": {
                        intf2: self.gen_hops(r) for intf2 in intfs if intf2 != intf
                    }
                } for intf in intfs},
                "Note": "Generated"
            }
            self.save(topo_info, settings)

    def save(self, topo_info, settings):
        base_path = topo_info.base_dir(self.args.output_dir)
        with open(os.path.join(base_path, StaticInfoGenerator.fname), "w") as f:
            json.dump(settings, f, indent=4)

class StaticInfoFromTopoFile:
    def __init__(self, args) -> None:
        super().__init__(args)

        with open(self.args.topo_config) as f:
            self.config = yaml.load(f, Loader=yaml.FullLoader)

    def generate(self, topo_dicts):
        pass

class StaticInfoFromCaida:
    """
    Generates a staticInfoConfig files for every AS in a topology with
    parameters chosen randomly with some more some less sensible
    distributions. Generation of the same ISD-AS for the
    same interfaces will yield the same random values.

    The values generated aren't coherent, in that the value
    for a link/path from one side is likely different for the same path
    from the other side.
    """
    fname = "staticInfoConfig.json"
    caida = caida.CaidaGraph()

    def __init__(self, args):
        self.args = args

    def gen_random_latency(self, r):
        return "0ms"

    def gen_latency(self, r, from_pos, to_pos):
        latency = self.caida.geo_data.get_latency_between_coords(from_pos, to_pos) + 1
        return round(r.gauss(latency, latency/10), 3)

    def gen_bandwith(self, r):
        return int(r.lognormvariate(1, 0.8)*2000000000)

    def gen_long(self, r):
        return 0

    def gen_lat(self, r):
        return 0

    def gen_addr(self, r):
        return "nowhere"

    def gen_hops(self, r):
        return int(random.uniform(1, 7))

    def gen_linktype(self, r):
        return random.choice(["direct", "multihop", "opennet"])

    def generate(self, topo_dicts):
        for topoInfo, topo in topo_dicts.items():
            # Flatten all interfaces into single dictionary
            intfs = {}
            for router in topo["border_routers"].values():
                intfs.update(router["interfaces"])

            r = random.Random(str(topoInfo))  # ISD-AS is seed

            settings = {
                "Latency": {intf: {
                    "Inter": self.gen_random_latency(r),
                    "Intra": {
                        intf2: f"{self.gen_latency(r, attrs['data'].get('geo', (0, 0)), attrs2['data'].get('geo', (0, 0)))}ms"
                            for intf2, attrs2 in intfs.items() if intf != intf2
                    }
                } for intf, attrs in intfs.items()},
                "Bandwidth": {intf: {
                    "Inter": self.gen_bandwith(r),
                    "Intra": {
                        intf2: self.gen_bandwith(r) for intf2 in intfs if intf2 != intf
                    }
                } for intf in intfs},
                "Linktype": {intf: self.gen_linktype(r) for intf in intfs},
                "Geo": {intf: {
                    "Latitutde": attrs["data"].get("geo", [0, 0])[0],
                    "Longitude": attrs["data"].get("geo", [0, 0])[1],
                    "Address": attrs["data"].get("location", "unknown"),
                } for intf, attrs in intfs.items()},
                "Hops": {intf: {
                    "Intra": {
                        intf2: self.gen_hops(r) for intf2 in intfs if intf2 != intf
                    }
                } for intf in intfs},
                "Note": "Generated"
            }
            base_path = topoInfo.base_dir(self.args.output_dir)
            with open(os.path.join(base_path, StaticInfoGenerator.fname), "w") as f:
                json.dump(settings, f, indent=4)
