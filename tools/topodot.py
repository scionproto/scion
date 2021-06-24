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

from plumbum import cli, local
from typing import Dict, List, NamedTuple

from python.lib.types import LinkType
from python.topology.topo import LinkEP


class TopoDot(cli.Application):
    show = cli.Flag(["-s", "--show"],
                    help="Run dot and show the graph, instead of only outputting the dot file.")

    def main(self, topofile):
        if self.show:
            prefix = pathlib.PurePath(topofile).stem + '-'
            with tempfile.NamedTemporaryFile(prefix=prefix, suffix='.png') as tmp:
                dot = local['dot']
                xdg_open = local['xdg-open']
                p = dot.popen(('-Tpng', '-o', tmp.name), encoding='utf-8')
                p.stdin.write(topodot(topofile))
                p.communicate()
                xdg_open(tmp.name)
        else:
            sys.stdout.write(topodot(topofile))


class Link(NamedTuple):
    a: LinkEP
    b: LinkEP
    type: str


def topodot(topofile) -> str:
    with open(topofile, 'r') as f:
        topo_config = yaml.safe_load(f)
    links = topo_links(topo_config)
    return 'digraph topo {\n%s\n}\n' % \
           '\n'.join('\t"%s" -> "%s"%s' %
                     (link.a, link.b, fmt_attrs(link_attrs(link)))
                     for link in links)


def fmt_attrs(attrs: Dict[str, str]) -> str:
    if attrs:
        return '[' + ';'.join('%s=%s' % (k, v) for k, v in attrs.items()) + ']'
    else:
        return ''


def link_attrs(link: Link) -> Dict[str, str]:
    attrs = {
        'taillabel': link.a.ifid,
        'headlabel': link.b.ifid,
        'labelfontcolor': 'gray50',
        'labelfontsize': '10.0',
    }
    if link.type in [LinkType.CORE, LinkType.PEER]:
        attrs['constraint'] = 'false'
        attrs['dir'] = 'none'
    if link.type == LinkType.PEER:
        attrs['constraint'] = 'false'
        attrs['dir'] = 'none'
        attrs['style'] = 'dotted'
    return attrs


def topo_links(topo_config) -> List[Link]:
    return [
        Link(a=LinkEP(link['a']),
             b=LinkEP(link['b']),
             type=link['linkAtoB'].lower())
        for link in topo_config['links']
    ]


if __name__ == "__main__":
    TopoDot.run()
