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

import json
import logging
import networkx as nx
import sys

from collections import deque

DEFAULT_ADCONFIGURATIONS_FILE = 'ADConfigurations.json'
ISD_AD_ID_DIVISOR = '-'
MAX_CORE_ADS = 5

output_graph = True

def parse(topo_file, ISD_NUM):
    """
    Parses the topo_file into a SCION ISD numbered - ISD_NUM
    """
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
                ad_id = values[0]
                isd_ad_id = ISD_AD_ID_DIVISOR.join([str(ISD_NUM), ad_id])
                original_graph.add_node(isd_ad_id, is_core=False)
                num_outedges.append((isd_ad_id, int(values[3])))

        if parsing_edges:
            if line == "\n":
                parsing_edges = False
            else:
                values = line.split("\t")
                source_isd_ad_id = ISD_AD_ID_DIVISOR.join([str(ISD_NUM),
                                                          values[1]])
                dest_isd_ad_id = ISD_AD_ID_DIVISOR.join([str(ISD_NUM),
                                                         values[2]])
                original_graph.add_edge(source_isd_ad_id, dest_isd_ad_id)

        if values[0] == "Nodes:":
            parsing_nodes = True
        elif values[0] == "Edges:":
            parsing_edges = True

    NUM_CORE_ADS = min(MAX_CORE_ADS, int(len(original_graph.nodes())/10))
    num_outedges = sorted(num_outedges, key=lambda tup: tup[1],
                          reverse=True)
    core_ads = [(i[0]) for i in num_outedges[:NUM_CORE_ADS]]
    core_ad_graph = original_graph.subgraph(core_ads)

    # Ensuring that core ad graph is connected
    if not nx.is_connected(core_ad_graph):
        # If not connected, the new core ad graph is formed from 
        # the largest connected component. Nodes are added to it from its 
        # neighbors to make size of core_ad_graph = NUM_CORE_ADS
        graphs = list(nx.connected_component_subgraphs(core_ad_graph))
        graphs = sorted(graphs, key=lambda graph: len(graph.nodes()), 
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
                                key=lambda tup: len(original_graph[tup]), 
                                reverse=True)
        core_ads = core_ads + neighbor_nodes[:num_extra_nodes]
        core_ad_graph = original_graph.subgraph(core_ads)
        print neighbor_nodes[:num_extra_nodes]

    print(core_ad_graph.nodes(), core_ad_graph.edges())
    final_graph = nx.DiGraph()
    for core_ad in core_ads:
        original_graph.node[core_ad]['color'] = 'red'
        original_graph.node[core_ad]['is_core'] = True
        final_graph.add_node(core_ad, color='red', is_core=True)
    for routing_edge in core_ad_graph.edges():
        final_graph.add_edge(routing_edge[0], routing_edge[1],
                             label='ROUTING', color='red')
        final_graph.add_edge(routing_edge[1], routing_edge[0],
                             label='ROUTING', color='red')
    # BFS
    queue = deque(core_ads)
    level = dict()
    for node in core_ads:
        level[node] = 1
    visited = dict()
    for core_ad in core_ads:
        visited[core_ad] = 1
    while queue:
        node = queue.popleft()
        for neighbor in original_graph.neighbors(node):
            if neighbor in core_ads:
                continue
            elif visited.get(neighbor) == None:
                final_graph.add_node(neighbor, is_core=False)
                final_graph.add_edge(node, neighbor, label='CHILD',
                                     color='green')
                final_graph.add_edge(neighbor, node, label='PARENT',
                                     color='green')
                visited[neighbor] = 1
                queue.append(neighbor)
                level[neighbor] = level[node] + 1
            elif neighbor not in final_graph.predecessors(node):
                if level[neighbor] == level[node]:
                    final_graph.add_edge(node, neighbor, label='PEER',
                                         color='blue')
                    final_graph.add_edge(neighbor, node, label='PEER',
                                         color='blue')
                else:
                    final_graph.add_edge(node, neighbor, label='CHILD',
                                         color='green')
                    final_graph.add_edge(neighbor, node, label='PARENT',
                                         color='green')
        visited[node] = 1

    assert len(original_graph.nodes()) == len(final_graph.nodes())
    assert 2*len(original_graph.edges()) == len(final_graph.edges())
    # print(final_graph.nodes(data=True), final_graph.edges())
    if output_graph:
        # convert to a graphviz agraph
        A = nx.to_agraph(final_graph)
        A.layout(prog='dot')
        img_file = topo_file.split('.')[0] + ".png"
        A.draw(img_file)
    json_convert(final_graph)

def json_convert(graph):
    """
    Converts graph object into json format and dumps it in
    DEFAULT_ADCONFIGURATIONS_FILE. The name of nodes in graph should be in
    the format {ISD}-{AD}
    """
    topo_dict = dict()
    topo_dict["default_subnet"] = "127.0.0.0/8"
    for isd_ad_id in graph.nodes():
        func_labels = lambda x: graph.edge[isd_ad_id][x]['label']
        list_labels = [func_labels(x) for x in list(graph.edge[isd_ad_id])]
        topo_dict[isd_ad_id] = {"beacon_servers": 1,
                                "certificate_servers": 1,
                                "path_servers": 1
                                }
        if graph.node[isd_ad_id]['is_core']:
            topo_dict[isd_ad_id]["level"] = "CORE"
        elif "CHILD" not in list_labels:
            topo_dict[isd_ad_id]["level"] = "LEAF"
        else:
            topo_dict[isd_ad_id]["level"] = "INTERMEDIATE"
        links = dict()
        cert_issuer = None
        for isd_ad_id_neighbor in graph.neighbors(isd_ad_id):
            links[isd_ad_id_neighbor] = \
                graph.edge[isd_ad_id][isd_ad_id_neighbor]['label']
            if links[isd_ad_id_neighbor] == "PARENT":
                cert_issuer = isd_ad_id_neighbor
        topo_dict[isd_ad_id]["links"] = links
        if cert_issuer != None:
            topo_dict[isd_ad_id]["cert_issuer"] = cert_issuer

    with open(DEFAULT_ADCONFIGURATIONS_FILE, 'w') as topo_fh:
        json.dump(topo_dict, topo_fh, sort_keys=True, indent=4)

def main():
    """
    Main function
    """
    if len(sys.argv) != 2:
        logging.error("run: %s topo_file", sys.argv[0])
        sys.exit()
    parse(sys.argv[1], 1)

if __name__ == "__main__":
    main()
