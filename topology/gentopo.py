import os, yaml

class Topo:
    def __init__(self) -> None:
        self.AS = set()
        self.links = {}

    def add_core(self, isd):
        IA = f"{isd}-ff00:0:{100 + len(self.AS):03}"
        self.AS.add(IA)
        self.links[IA] = set()
        return IA

    def add_link(self, f, t):
        if f < t:
            f, t + t, f

        self.links[f] = self.links.get(f, set()) | {t}

    def generate(self, fname):
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



def create_fully_connected_core(n):
    t = Topo()
    ASs = [t.add_core(i+1) for i in range(n)]
    for as1 in ASs:
        for as2 in ASs:
            if as1 != as2:
                t.add_link(as1, as2)

    t.generate(f"fully_connected_{n}c.topo")


if __name__ == "__main__":
    create_fully_connected_core(3)
