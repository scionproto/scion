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

import argparse
import json
import logging
import networkx as nx
import os
import sys

from collections import deque

DEFAULT_ADCONFIGURATIONS_FILE = 'ADConfigurations.json'
ISD_AD_ID_DIVISOR = '-'
MAX_CORE_ADS = 7
MIN_ISD_NUM = 1


def parse(brite_files):
    """
    Parse a list of topology files each into a seperate ISD

    :param brite_files: list of brite output files to be converted
    :type brite_files: list
    """
    ISD_dict = dict()
    core_ad_dict = dict()
    ISD_number = MIN_ISD_NUM
    final_graph = nx.DiGraph()
    core_ads = list()
    for brite_file in brite_files:
        if not os.path.isfile(brite_file):
            logging.error(brite_file + " file missing.")
            sys.exit()
        result = _parse(brite_file, ISD_number)
        ISD_dict[ISD_number] = result[0]
        core_ad_dict[ISD_number] = result[1]
        core_ads += core_ad_dict[ISD_number]
        final_graph = nx.union(final_graph, ISD_dict[ISD_number])
        ISD_number += 1

    NUM_ISDS = ISD_number - 1
    assert NUM_ISDS == len(brite_files)
    print("Number of ISD's is {}".format(NUM_ISDS))

    core_ad_model_graph = nx.cycle_graph(NUM_ISDS)
    # Core AD connections: Connecting each core AD in an ISD with
    # every other Core AD in a cycle fashion
    for src_isd_id in range(MIN_ISD_NUM, NUM_ISDS + 1):
        for dest_isd_id in range(MIN_ISD_NUM, NUM_ISDS + 1):
            src_core_ads = core_ad_dict[src_isd_id]
            dest_core_ads = core_ad_dict[dest_isd_id]
            if core_ad_model_graph[src_isd_id - 1].get(dest_isd_id - 1) == None:
                continue
            for src_ad in src_core_ads:
                for dest_ad in dest_core_ads:
                    final_graph.add_edge(src_ad, dest_ad,
                                         label='ROUTING', color='red')
    # core_ad_graph = final_graph.subgraph(core_ads)
    # print(core_ad_graph.nodes(), core_ad_graph.edges())
    assert nx.is_connected(final_graph.to_undirected())
    return final_graph

def _parse(topo_file, ISD_NUM):
    """
    Parses the topo_file into a SCION ISD numbered - ISD_NUM 

    :param topo_file: A brite output file to be converted
    :type topo_file: str
    :param ISD_NUM: ISD Number of the graph to be generated 
    :type ISD_NUM: int
    :returns: the newly created Graph.
    TODO
    :rtype: :class:`networkx.DiGraph`
    """
    fd = open(topo_file, 'r')
    nodes_count = 0
    edges_count = 0

    original_graph = nx.Graph()
    num_outedges = list()
    for line in fd:
        values = line.split(" ")
        if nodes_count > 0:
            nodes_count -= 1
            values = line.split("\t")
            ad_id = values[0]
            isd_ad_id = ISD_AD_ID_DIVISOR.join([str(ISD_NUM), ad_id])
            original_graph.add_node(isd_ad_id, is_core=False)
            num_outedges.append((isd_ad_id, int(values[3])))

        if edges_count > 0:
            edges_count -= 1
            values = line.split("\t")
            source_isd_ad_id = ISD_AD_ID_DIVISOR.join([str(ISD_NUM),
                                                      values[1]])
            dest_isd_ad_id = ISD_AD_ID_DIVISOR.join([str(ISD_NUM),
                                                     values[2]])
            original_graph.add_edge(source_isd_ad_id, dest_isd_ad_id)

        if values[0] == "Nodes:":
            nodes_count = int(values[2])
        if values[0] == "Edges:":
            edges_count = int(values[2])

    # print(nx.minimum_edge_cut(original_graph))

    NUM_CORE_ADS = min(MAX_CORE_ADS, int(len(original_graph.nodes()) / 10))
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

        # Sorting nodes based on their outdegree in the original graph
        neighbor_nodes = sorted(neighbor_nodes, 
                                key=lambda tup: len(original_graph[tup]), 
                                reverse=True)
        core_ads = core_ads + neighbor_nodes[:num_extra_nodes]
        core_ad_graph = original_graph.subgraph(core_ads)

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

    print("ISD {} has {} AS's".format(ISD_NUM, len(original_graph.nodes())))
    print("Core AD's are:")
    print(core_ad_graph.nodes())
    # convert to a graphviz agraph(NOTE: requires pygraphviz)
    if False:
        A = nx.to_agraph(final_graph)
        A.layout(prog='dot')
        img_file = topo_file.split('.')[0] + ".png"
        A.draw(img_file)
    return(final_graph, core_ad_graph.nodes())

def json_convert(graph):
    """
    Converts graph into json format and dumps it in
    DEFAULT_ADCONFIGURATIONS_FILE. The name of nodes in graph should be in
    the format {ISD}-{AD}

    :param graph: A graph to be dumped into the json file
    :type graph: :class: `networkx.DiGraph`
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
    if len(sys.argv) < 2:
        logging.error("run: %s -h", sys.argv[0])
        sys.exit()

    parser = argparse.ArgumentParser(description='SCION Topology generator')
    parser.add_argument('-a', action='append', dest='collection',
                        default=[],
                        help='Add a new isd',
                        )
    # parser.add_argument('-dir', action='store_true', default=False,
    #                     dest='from_directory',
    #                     help='Convert all files in a directory into corresponding isd')
    # parser.add_argument('-s', action='store', dest='directory_name',
    #                     help='Directory name')

    results = parser.parse_args()
    print(results.collection)
    # from_directory = results.from_directory
    # directory_name = results.directory_name

    # if from_directory:
    #     if not os.path.isdir(directory_name):
    #         logging.error(directory_name + " directory missing.")
    #         sys.exit()
    brite_files = results.collection
    scion_graph = parse(brite_files)
    json_convert(scion_graph)

if __name__ == "__main__":
    main()
