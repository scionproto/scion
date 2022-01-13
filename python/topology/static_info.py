import os, random, json

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
    def __init__(self, args):
        self.args = args

        # self.gen_latency = lambda r: f"{int(r.lognormvariate(1, 0.8)*60)}ms"
        self.gen_latency = lambda r: f"{10}ms"
        self.gen_bandwith = lambda r: int(r.lognormvariate(1, 0.8)*2000000000)
        self.gen_long = lambda r: 0
        self.gen_lat = lambda r: 0
        self.gen_addr = lambda r: "nowhere"
        self.gen_hops = lambda r: int(random.uniform(1, 7))
        self.gen_linktype = lambda r: random.choice(["direct", "multihop", "opennet"])


    def generate(self, topo_dicts):
        for topoInfo, topo in topo_dicts.items():
            intfs = [intf for router in topo["border_routers"].values()
                            for intf in router["interfaces"].keys() ]
            r = random.Random(str(topoInfo)) # ISD-AS is seed
            settings = {
                "Latency": {intf : {
                    "Inter": self.gen_latency(r),
                    "Intra" : {
                        intf2: self.gen_latency(r) for intf2 in intfs if intf2 != intf
                    }
                } for intf in intfs},
                "Bandwidth": {intf : {
                    "Inter": self.gen_bandwith(r),
                    "Intra" : {
                        intf2: self.gen_bandwith(r) for intf2 in intfs if intf2 != intf
                    }
                } for intf in intfs},
                "Linktype": {intf : self.gen_linktype(r) for intf in intfs},
                "Geo": {intf : {
                    "Latitutde": self.gen_lat(r),
                    "Longitude": self.gen_long(r),
                    "Address": self.gen_addr(r),
                } for intf in intfs},
                "Hops": {intf : {
                    "Intra": {
                        intf2: self.gen_hops(r) for intf2 in intfs if intf2 != intf
                        }
                    } for intf in intfs},
                "Note": "Generated"
            }
            base_path = topoInfo.base_dir(self.args.output_dir)
            with open(os.path.join(base_path, StaticInfoGenerator.fname), "w") as f:
                json.dump(settings, f, indent=4)
