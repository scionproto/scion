import itertools
import os, yaml, networkx as nx, matplotlib.pyplot as plt
import random, mpu

import caida_gen as caida

def add_ia_labels(G):
    for i, node in enumerate(G.nodes):
        i += 1
        G.nodes[node]["ia"] = f"{i}-ff00:0:{i}"
    return G

def gen_topo(as_ia_mapping):
    G = full_graph(3)
    G = add_ia_labels(G)
    return nx_to_topo(G)

def nx_to_topo(G):
    if not "ia" in G.nodes[0]:
        raise Exception
    return {
        "ASes": {
            d['ia']: {
                "core": True,
                "voting": True,
                "authoritative": True,
                "issuing": True
            } for n, d in G.nodes(data=True)
        },
        "links": [
            {
                "a": G.nodes[f]['ia'],
                "b": G.nodes[t]['ia'],
                "linkAtoB": "CORE",
                "mtu": 1280,
            } for f, t in G.edges
        ]
    }

def dump_nx_graph_topo(G, filename):
    res = gen_topo(G)
    path = os.path.join("topology", filename + ".topo")
    with open(path,  "w") as f:
        yaml.dump(res, f)

    print("Saved topology to", path)


def full_graph(n):
    G = nx.Graph()
    G.add_nodes_from(range(n))
    G.add_edges_from(itertools.combinations(range(n), 2))
    return G

def show_nxgraph(G):
    nx.draw(G, pos=nx.circular_layout(G), node_color='r', edge_color='b', with_labels=True)
    plt.show()



if __name__ == "__main__":
    #show_nxgraph(topo_to_nxgraph(complete_topo(6)))
    #show_nxgraph(topo_to_nxgraph(nx_as_topo_cores(5)))
    g = caida.nx_from_caida_tier1("topology/cycle-aslinks.l7.t1.c008040.20200101.txt")
    dump_nx_graph_topo(g, "caida_tier_1s")

