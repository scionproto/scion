#!/usr/bin/env python3

# Copyright 2021 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pathlib
import sys
import tempfile
import yaml
from collections import defaultdict

from plumbum import cli, local
from typing import Dict, List, NamedTuple

from topology.topo import LinkEP, LinkType, TopoID

graph_fmt = """digraph topo {{
\tnode [margin=0.2]
\tedge [labeldistance=1.1,labelfontsize=8.0,labelfontcolor=gray40]

{}
}}
"""

isd_fmt = """\tsubgraph cluster_{isd} {{
\t\tmargin=16
\t\tlabel="{isd}"

{core}

{rest}
\t}}
"""

core_fmt = """\t\tsubgraph cluster_{isd}_core {{
\t\t\tmargin=25
\t\t\tlabel="Core {isd}"

{core}
\t\t}}
"""


class TopoDot(cli.Application):
    show = cli.Flag(
        ["-s", "--show"],
        help="Run dot and show the graph, "
        + "instead of only outputting the dot file.",
    )

    def main(self, topofile):
        if self.show:
            prefix = pathlib.PurePath(topofile).stem + "-"
            with tempfile.NamedTemporaryFile(prefix=prefix, suffix=".png") as tmp:
                dot = local["dot"]
                xdg_open = local["xdg-open"]
                p = dot.popen(("-Tpng", "-o", tmp.name), encoding="utf-8")
                p.stdin.write(topodot(topofile))
                p.communicate()
                xdg_open(tmp.name)
        else:
            sys.stdout.write(topodot(topofile))


class Link(NamedTuple):
    a: LinkEP
    b: LinkEP
    type: LinkType


def topodot(topofile) -> str:
    with open(topofile, "r") as f:
        topo_config = yaml.safe_load(f)

    links = topo_links(topo_config)
    clusters = topo_clusters(topo_config)

    def format_nodes(indent, ases):
        fmt = "\t" * indent + '"%s"'
        return "\n".join(fmt % isd_as for isd_as in ases)

    def format_links(indent, links):
        fmt = "\t" * indent + '"%s" -> "%s"%s'
        return "\n".join(
            fmt % (link.a, link.b, fmt_attrs(link_attrs(link))) for link in links
        )

    formatted_clusters = []
    for isd in sorted(clusters.keys()):
        core = core_fmt.format(
            isd=isd,
            core=format_nodes(3, clusters[isd]["core"]),
        )
        rest = format_nodes(2, clusters[isd]["noncore"])
        formatted_clusters.append(isd_fmt.format(isd=isd, core=core, rest=rest))
    rest = format_links(1, links)
    return graph_fmt.format("\n".join(c for c in formatted_clusters + [rest]))


def fmt_attrs(attrs: Dict[str, str]) -> str:
    if attrs:
        return "[" + ";".join("%s=%s" % (k, v) for k, v in attrs.items()) + "]"
    else:
        return ""


def link_attrs(link: Link) -> Dict[str, str]:
    attrs = {
        "taillabel": link.a.ifid,
        "headlabel": link.b.ifid,
    }
    if link.type == LinkType.CORE:
        attrs["dir"] = "none"
    if link.type == LinkType.PEER:
        attrs["constraint"] = "false"
        attrs["dir"] = "none"
        attrs["style"] = "dotted"
    return attrs


def topo_links(topo_config) -> List[Link]:
    return [
        Link(
            a=LinkEP(link["a"]),
            b=LinkEP(link["b"]),
            type=LinkType[link["linkAtoB"].upper()],
        )
        for link in topo_config["links"]
    ]


def topo_clusters(topo_config) -> Dict[str, Dict[str, List[str]]]:
    clusters = defaultdict(lambda: defaultdict(list))
    for raw_isd_as, config in topo_config["ASes"].items():
        isd_as = TopoID(raw_isd_as)
        if config.get("core"):
            clusters[isd_as.ISD()]["core"].append(str(isd_as))
        else:
            clusters[isd_as.ISD()]["noncore"].append(str(isd_as))
    return clusters


if __name__ == "__main__":
    TopoDot.run()
