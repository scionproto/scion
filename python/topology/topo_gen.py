import os, yaml, networkx as nx, matplotlib.pyplot as plt
import random


class Topo:
    def __init__(self) -> None:
        self.AS = set()
        self.links = {}

    def add_core(self, isd):
        IA = f"{isd}-ff00:0:{100 + len(self.AS)}"
        self.AS.add(IA)
        self.links[IA] = set()
        return IA

    def add_link(self, f, t):
        if f < t:
            f, t + t, f

        self.links[f] = self.links.get(f, set()) | {t}

    def save(self, fname):
        res = {
            "ASes": {
                AS: {
                    "core": True,
                    "voting": True,
                    "authoritative": True,
                    "issuing": True
            } for AS in self.AS
            },
            "links": [
                {
                    "a": f,
                    "b": t,
                    "linkAtoB": "CORE",
                    "mtu": 1280,
                } for f, ts in self.links.items() for t in ts
            ]
        }

        with open(os.path.join("topology", fname), "w") as f:
            yaml.dump(res, f)

def complete_topo(n):
    return nx_to_topo(nx.complete_graph(n))

def random_topo(n):
    r = random.Random(0)
    c = 0
    t = Topo()
    ases = []
    for _ in range(n):
        if r.random() < 0.2:
            c += 1
        ases.append(t.add_core(c))
    for as1 in ases:
        for as2 in ases:
            if as1 != as2 and r.random() < 0.3:
                t.add_link(as1, as2)

    return t

def nx_to_topo(G):
    top = Topo()
    ass = [(top.add_core(i), i) for i in range(len(G))]
    for as1, i1 in ass:
        for as2, i2 in ass:
            if as1 != as2 and G.has_edge(i1, i2):
                top.add_link(as1, as2)
    return top


def as_topo(n):
    G = nx.random_internet_as_graph(n, 0)
    return nx_to_topo(G)



def topo_to_nxgraph(t):
    G = nx.Graph()
    for AS in t.AS:
        G.add_node(AS)
    for f, ts in t.links.items():
        for t in ts:
            G.add_edge(f, t)
    return G


def show_nxgraph(G):
    nx.draw(G, pos=nx.circular_layout(G), node_color='r', edge_color='b', with_labels=True)
    plt.show()


if __name__ == "__main__":
    #show_nxgraph(topo_to_nxgraph(complete_topo(6)))
    show_nxgraph(topo_to_nxgraph(complete_topo(5)))

