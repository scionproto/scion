import os
import random

import mpu
import networkx as nx
from bidict import bidict
from thefuzz import process

from python.topology import topo_gen as topo

caida_path = os.path.join("python", "topology", "caida")


def open_caida(path, flag="r"):
    return open(os.path.join(caida_path, path), flag)

def gen_ia(i):
    return f"{i}-ff00:0:{i}"

def ia_from_link_name(name):
    return name.split("#")[0]

class GeoData:
    locations_file_name = "201603.locations.txt"
    rel_geo_file_name = "201603.as-rel-geo.txt"
    def __init__(self):
        self.loc2pos = {}
        with open_caida(self.locations_file_name) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                lid, continent, country, region, city, lat, long, pop = line.split(
                    "|")
                self.loc2pos[lid] = (float(lat), float(long))

        self.rel2loc = {}
        with open_caida(self.rel_geo_file_name) as f:
            for line in f:
                if line.startswith("#"):
                    continue
                as1, as2, desc1, *_ = line.split("|")
                lid, *_ = desc1.split(",")
                self.rel2loc[(int(as1), int(as2))] = lid

    def get_coord_of_loc(self, loc):
        return [*self.loc2pos[loc]]


    @staticmethod
    def get_distance_between_coords(p1, p2):
        return mpu.haversine_distance(p1, p2)

    def get_distance_between_locs(self, loc1, loc2):
        c1, c2 = self.get_coords(loc1), self.get_coords(loc2)
        return self.get_distance_between_coords(c1, c2)

    def get_loc_of_rel(self, as1, as2):
        if as1 > as2:
            as1, as2 = as2, as1
        loc = self.rel2loc[(as1, as2)]
        return loc

    def get_coord_of_rel(self, as1, as2):
        loc = self.get_loc_of_rel(as1, as2)
        return self.get_coord_of_loc(loc)

    def has_loc_of_rel(self, as1, as2):
        if as1 > as2:
            as1, as2 = as2, as1
        return (as1, as2) in self.rel2loc

    @staticmethod
    def distance_to_latency(dist_km):
        c_km_ms = 300
        return dist_km/c_km_ms

    @staticmethod
    def get_latency_between_coords(pos1, pos2):
        dist = GeoData.get_distance_between_coords(pos1, pos2)
        return GeoData.distance_to_latency(dist)

    def match_loc(self, match_loc):
        loc, score = process.extractOne(match_loc, self.get_all_locations())
        if score > 60:
            return loc
        else:
            raise Exception(f"Couldn't match location {loc}, certainty: {score}")

    def get_all_locations(self):
        return self.loc2pos.keys()

class CaidaGraph:
    file_name = "cycle-aslinks.l7.t1.c008040.20200101.txt"

    def __init__(self):
        """
        # List taken from wikipedia

        self.selected_ASes = [
            7018, 3320, 3257,
            6830, 3356, 4549,
            2914, 5511, 3491,
            1239, 6453, 6762,
            1299, 12956, 701,
            6461
        ]
        """
        self.selected_ASes = [
            3356, 1299, 174, 3257, 6762, 2914, 6939
            ]

        self.geo_data = GeoData()
        self.r = random.Random()
        self.as_isd_map = bidict({asid: gen_ia(i+1) for i,
                                  asid in enumerate(self.selected_ASes)})

    def enumerate_links(self):
        def get_froms_tos(line):
            parts = line.split()
            _, fs_str, ts_str, *_ = parts
            fs = [int(f) for f in ",".join(fs_str.split("_")).split(",")]
            ts = [int(t) for t in ",".join(ts_str.split("_")).split(",")]
            return fs, ts

        with open_caida(self.file_name) as f:
            for line in f:
                if not line.startswith("D"):
                    continue
                fs, ts = get_froms_tos(line)
                for f in fs:
                    for t in ts:
                        if f != t and\
                                f in self.selected_ASes and\
                                t in self.selected_ASes:

                            f_ia, t_ia = self.as_isd_map[f], self.as_isd_map[t]
                            yield f_ia, t_ia

    def get_nx_graph(self):
        g = nx.MultiGraph()
        for f, t in self.enumerate_links():
            f_as, t_as = self.as_isd_map.inv[f], self.as_isd_map.inv[t]

            if not self.geo_data.has_loc_of_rel(f_as, t_as):
                continue

            loc = self.geo_data.get_loc_of_rel(f_as, t_as)
            lat, long = self.geo_data.get_coord_of_rel(f_as, t_as)

            g.add_edge(f, t, geo=[lat, long], location=loc)

        return g
