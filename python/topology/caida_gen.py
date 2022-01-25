import mpu
import python.topology.topo_gen as topo
import networkx as nx

class LidLocations:
    """
    Reads a caida locations file, mapping location ids (lids) of form Aabenraa-83-DK to latitude, lognitute,
    and allows accurate cacluation of distance in km between two lids.
    """
    def __init__(self, path="topology/201603.locations.txt"):
        self.lid2pos = {}
        with open(path) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                lid, continent, country, region, city, lat, long, pop = line.split("|")
                self.lid2pos[lid] = (float(lat), float(long))

    def get_coords(self, lid):
        return self.lid2pos[lid]

    def distance_between(self, lid1, lid2):
        c1, c2 = self.get_coords(lid1), self.get_coords(lid2)
        return mpu.haversine_distance(c1, c2)


class LinkLocations:
    """
    Reads a caida as-rel-geo file, mapping links between AS (identified by two AS numbers) to geographic location IDs.
    E.g. get_loc(1, 2) -> "Aabenraa-83-DK"

    Also allows calculation of distance between two egress links of an AS.
    distance_between(1, 2, 3) -> distance between link of as 2 to as 1 and link of as 2 to as 3.
    """
    def __init__(self, path="topology/201603.as-rel-geo.txt", lid_locs=None):
        self.link2lid = {}
        with open(path) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                as1, as2, desc1, *_ = line.split("|")
                lid, *_ = desc1.split(",")
                self.link2lid[(int(as1), int(as2))] = lid

        self.lid2pos = LidLocations() if lid_locs is None else lid_locs

    def get_loc(self, as1, as2):
        if as1 > as2:
            as1, as2 = as2, as1
        return self.link2lid.get((as1, as2), "London-ENG-UK")

    def distance_beteen(self, as1, ascenter, as2):
        lid1, lid2 = self.get_loc(as1, ascenter), self.get_loc(ascenter, as2)
        return self.lid2pos.distance_between(lid1, lid2)



def read_caida(path):
    with open(path) as f:
        for line in f:
            if not line.startswith("D"):
                continue
            parts = line.split()
            _, fs, ts, *_ = parts
            for f in ",".join(fs.split("_")).split(","):
                for t in ",".join(ts.split("_")).split(","):
                    if f != t:
                        yield int(f), int(t)

def nx_from_caida_tier1(path):
    core_AS_numbers = {7018, 3320, 3257, 6830, 3356, 4549, 2914, 5511, 3491, 1239, 6453, 6762, 1299, 12956, 701, 6461}
    g = nx.Graph()
    llocs = LinkLocations()
    for f, t in read_caida(path):
        if f in core_AS_numbers and t in core_AS_numbers:
            g.add_edge(f, t)

    a, b, c, *_ = core_AS_numbers
    print(f"Distance {a}-{b}-{c}: {llocs.distance_beteen(a, b, c)}, locations:\n- {a}-{b}: {llocs.get_loc(a, b)}\n- {b}-{c}: {llocs.get_loc(b, c)}", )
    print(len(g.edges) ,len(g.nodes))
    return g



_l2loc = LinkLocations()

def distance_between(f,c, t):
    return _l2loc.distance_beteen(f,c, t)
