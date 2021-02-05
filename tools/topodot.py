#!/usr/bin/env python3

import sys
import yaml

from python.topology.topo import LinkEP
from python.lib.types import LinkType

from plumbum import cli
from typing import NamedTuple, Dict


class Link(NamedTuple):
    a: LinkEP
    b: LinkEP
    type: str


class TopoDot(cli.Application):
    def main(self, topofile):
        with open(topofile, 'r') as f:
            topo_config = yaml.safe_load(f)
        sys.stdout.write(topodot(topo_config))


def topodot(topo_config):
    links = topo_links(topo_config)

    return 'digraph topo {\n' + '\n'.join('\t "%s" -> "%s"%s' %
                                          (link.a, link.b, fmt_attrs(link_attrs(link)))
                                          for link in links) + '\n}\n'


def fmt_attrs(attrs: Dict[str, str]):
    if attrs:
        return '[' + ';'.join('%s=%s' % (k, v) for k, v in attrs.items()) + ']'
    else:
        return ''


def link_attrs(link: Link) -> Dict[str, str]:
    attrs = {
        'headlabel': link.a.ifid,
        'taillabel': link.b.ifid,
    }
    if link.type in [LinkType.CORE, LinkType.PEER]:
        attrs['constraint'] = 'false'
        attrs['dir'] = 'none'
    if link.type == LinkType.PEER:
        attrs['constraint'] = 'false'
        attrs['dir'] = 'none'
        attrs['style'] = 'dotted'
    return attrs


def topo_links(topo_config):
    return [
        Link(a=LinkEP(link['a']),
             b=LinkEP(link['b']),
             type=link['linkAtoB'].lower())
        for link in topo_config['links']
    ]


if __name__ == "__main__":
    TopoDot.run()
