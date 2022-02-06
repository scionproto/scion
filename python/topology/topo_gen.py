import copy
import os
import random
from collections import defaultdict
from pprint import pprint

import networkx as nx
import yaml
from bidict import bidict

from . import caida_gen as caida

caida.caida_path = "python/topology/caida"

def gen_better_topo(
    n=40, # Number of ISDs == number of core ASs
    k=3, # Connectivity of ISDs
    sprinkle=True,
    only_originate_at=None,
    multi_link_ixs=True,
):
    """
    Generates a topology as follows:

    First, generate a (non-multi) graph with n nodes that is k connected with minimal #edges
    Then, if sprinkle is True, add n edges randomly.

    Each node stands for an AS; each AS is assumed to be part of a separate ISD.
    Each edge in that graph so far represents an IX point between two ASes.

    Each IX point is assigned a random location on the planet according to caida's location dataset.
    The graph is then extended with 1 to 5 links per IX point.

    Latencies between links will later be derived from their geographic locations.
    Thus, all links at the same IX will have approximately the same latencies to all other possible
    points on the graph. Therefore, all links at the same IX will be put into a propagation interface group
    _if_ there is more than one link at the given IX.

    Of each IX that has more than one link, one link is randomly selected.
    All selected links are then added to one other optimization group targeting throughput.
    """
    r = random.Random(0)
    c = lambda l: r.choice(l)
    # Number of links per IX
    links_per_ix = lambda: r.choices([1, 2, 3, 4], weights=[2, 1, 1, 0.5], k=1)[0]


    # Generate graph by harary algo
    g = nx.hkn_harary_graph(k, n)
    g = nx.MultiGraph(g)

    if sprinkle:
        # Add a couple of random edges to spice things up
        for _ in range(len(g.edges())):
            f = c(list(g.nodes()))
            t = c(list(g.nodes()))
            if f != t:
                g.add_edge(f, t)

    g = nx.relabel_nodes(g, {i: caida.gen_ia(i+1) for i in list(g.nodes())})

    # Add random locations to each link
    geo = caida.GeoData()
    locs = list(geo.get_all_locations())
    random.shuffle(locs)

    for i, (edge, loc) in enumerate(zip(list(g.edges(data=True, keys=True)), locs)):
        f, t, k, d = edge
        g.add_edge(f, t, key=k, location=loc, geo=geo.get_coord_of_loc(loc), id=i+1, **d)

    def create_group(members, quality):
        return {
            "optimization target filters": [{"quality": quality}],
            "interfaces": members
        }

    # Each edge now represents one IX - now add multiple links per IX
    if multi_link_ixs:
        for f, t, d in list(g.edges(data=True)):
            for i in range(links_per_ix()-1):
                # Duplicate data, assign new id, add new edge
                new_d = copy.deepcopy(dict(d))
                id_ = len(g.edges())+1
                new_d["id"] = id_
                g.add_edge(f, t, **new_d)
                # Add edge to latency group

    # Now for each IX, create an interface group
    for f in list(g.nodes()):
        # Will contain {group_identifier: group}
        groups = {}
        targets = {}
        orders = defaultdict(list)
        # All locations of edges originating in f
        locations = {d["location"] for _, _, d in g.edges(f, data=True)}
        # One edge per IX will be selected as member of throughput group
        throughput_members = []
        for loc in locations:

            latency_members = [d["id"] for _, _, d in g.edges(f, data=True) if d["location"] == loc]
            if len(latency_members) >= 1:
                group_id = f"group_{len(groups)}"
                groups[group_id] = create_group(latency_members, "latency")
                throughput_members.append(r.choice(latency_members))

                for member in latency_members:
                    orders[member].append([group_id])
                targets[group_id] = {"quality": "latency", "direction": "forward"}


        if len(throughput_members) >= 1:
            groups[f"group_{len(groups)}"] = create_group(throughput_members, "throughput")

        originate = only_originate_at is None or f in only_originate_at or f == only_originate_at or f.split("-")[0] == only_originate_at
        # Overwrite data of node f
        g.nodes[f]["pqa"] = {
            "propagator": groups,
            "originator": {
                "optimization targets": targets,
                "origination order": dict(orders),
            } if originate else {}
        }



    print(f"Nodes: {len(g.nodes())}, edges: {len(g.edges())}")
    return g



def gen_caida_topo():
    caida_G = caida.CaidaGraph()
    G = caida_G.get_nx_graph()


def gen_from_simple(path):
    with open(path, "r") as f:
        topo = yaml.load(f, Loader=yaml.FullLoader)

    geo = caida.GeoData()

    as_id_to_ia = bidict()
    def add_as(i):
        if not i in as_id_to_ia:
            as_id_to_ia[i] = caida.gen_ia(len(as_id_to_ia)+1)

    def get_ia(i):
        add_as(i)
        return as_id_to_ia[i]

    g = nx.MultiGraph()
    for link in topo["links"]:
        a, b = link["a"], link["b"]
        a_ia, b_ia = get_ia(a), get_ia(b)

        fuzzy_loc = link["location"]
        loc = geo.match_loc(fuzzy_loc)
        coords = list(geo.get_coord_of_loc(loc))
        id_ = link.get("id", len(g.edges())+1)

        g.add_edge(a_ia, b_ia, location=loc, geo=coords, id=id_)

    for as_id, as_cfg in topo["pqa"].items():
        ia = get_ia(as_id)
        g.nodes[ia]["pqa"] = as_cfg

    return g



def nx_to_topo(g):
    return {
        "ASes": {
            n: {
                "core": True,
                "voting": True,
                "authoritative": True,
                "issuing": True,
                **d
            } for n, d in g.nodes(data=True)
        },
        "links": [
            {
                "a": f"{f}#{d['id']}",
                "b": f"{t}#{d['id']}",
                "linkAtoB": "CORE",
                "data": d,
            } for f, t, d in g.edges(data=True)
        ],
    }



def dump_topo(topo, topo_name):
    path = os.path.join("topology", topo_name + ".topo")
    with open(path,  "w") as f:
        # Remove &id *id links inside topo
        topo = copy.deepcopy(topo)
        yaml.safe_dump(topo, f)

    print("Saved topology to", path)

def gen_and_dump(n, k, sprinkle, originate=None, fname=None):
    g = gen_better_topo(n, k, sprinkle, originate)
    name = fname if fname is not None else f"topology/geo_gen_{n}n_{k}k_{'sprinkle' if sprinkle else ''}sprinkle_origin_{originate}"
    dump_topo(nx_to_topo(g), name)
    return name

if __name__ == "__main__":

    # caida_G = caida.CaidaGraph()
    # g = caida_G.get_nx_graph()

    # g = gen_from_simple("topology/test.simple.topo")

    # topo = nx_to_topo(g)
    # dump_topo(topo, "simple_test")

    pass
