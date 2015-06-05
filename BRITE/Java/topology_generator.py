# Copyright 2015 ETH Zurich
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
"""
:mod:`topology_generator` --- SCION topology generator
============================================
"""

import logging
import sys

import networkx as nx

output_graph = True

def parse(topo_file):
    fd = open(topo_file, 'r')
    parsing_nodes = False
    parsing_edges = False

    original_graph = nx.Graph()
    num_outedges = list()
    for line in fd:
        values = line.split(" ")
        
        if parsing_nodes:
            if line == "\n":
                parsing_nodes = False
            else:
                values = line.split("\t")
                original_graph.add_node(int(values[0]), is_core=False)
                num_outedges.append((int(values[0]), int(values[3])))

        if parsing_edges:
            if line == "\n":
                parsing_edges = False
            else:
                values = line.split("\t")
                original_graph.add_edge(int(values[1]), int(values[2]))

        if values[0] == "Nodes:":
            parsing_nodes = True
        elif values[0] == "Edges:":
            parsing_edges = True
    
    NUM_CORE_ADS = int(len(original_graph.nodes())/10)
    num_outedges = sorted(num_outedges, key=lambda tup:tup[1], 
                          reverse=True)
    core_ads = [(i[0]) for i in num_outedges[:NUM_CORE_ADS]]
    core_ad_graph = original_graph.subgraph(core_ads)

    # Ensuring that core ad graph is connected
    if not nx.is_connected(core_ad_graph):
        # If not connected, the new core ad graph is formed from 
        # the largest connected component. Nodes are added to it from its 
        # neighbors to make size of core_ad_graph = NUM_CORE_ADS
        graphs = list(nx.connected_component_subgraphs(core_ad_graph))
        graphs = sorted(graphs, key=lambda graph:len(graph.nodes()), 
                        reverse=True)
        core_ad_graph = graphs[0]
        core_ads = core_ad_graph.nodes()
        num_extra_nodes = NUM_CORE_ADS - len(core_ads)
        neighbor_nodes = set()
        for neighbor in [original_graph.neighbors(node) for node in core_ad_graph]:
            for node in neighbor:
                if node not in core_ad_graph.nodes():
                    neighbor_nodes.add(node)

        neighbor_nodes = sorted(neighbor_nodes, 
                                key=lambda tup:len(original_graph[tup]), 
                                reverse=True)
        core_ads = core_ads + neighbor_nodes[:num_extra_nodes]
        core_ad_graph = original_graph.subgraph(core_ads)
        print neighbor_nodes[:num_extra_nodes]

    print(core_ad_graph.nodes(), core_ad_graph.edges())

    for core_ad in core_ads:
        original_graph.node[core_ad]['color'] = 'red'
        original_graph.node[core_ad]['is_core'] = True

    print(original_graph.nodes(data=True))
    if output_graph:
        # convert to a graphviz agraph
        A=nx.to_agraph(original_graph)
        A.layout(prog='dot')
        A.draw('topo2.png')


def main():
    if len(sys.argv) != 2:
        logging.error("run: %s topo_file ",
                      sys.argv[0])
        sys.exit()

    parse(sys.argv[1])

if __name__ == "__main__":
    main()