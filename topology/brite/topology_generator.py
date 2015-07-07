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
# Stdlib
import argparse
import json
import logging
import os
import random
import sys
from collections import deque

# External Packages
import networkx as nx

DEFAULT_ADCONFIGURATIONS_FILE = 'ADConfigurations.json'
ISD_AD_ID_DIVISOR = '-'
MAX_CORE_ADS = 7
MIN_ISD_NUM = 1


def read_from_dir(dir_name):
    """
    Read all brite files from a directory

    :param dir_name: The directory in which files are to be converted
    :type dir_name: str

    :returns: list of files in the directory
    :rtype: list
    """
    if not os.path.isdir(dir_name):
        logging.error(dir_name + " directory missing.")
        sys.exit()
    # All files in the directory will be read
    list_files = [os.path.join(dir_name, f) for f in os.listdir(dir_name)
                  if os.path.isfile(os.path.join(dir_name, f))]
    if len(list_files) == 0:
        logging.error("No files in " + dir_name + ".")
        sys.exit()
    # Ordering the files w.r.t their name
    list_files = sorted(list_files)
    print("Files being converted are: \n{}\n".format(list_files))
    return list_files


def gen_base_isd_graph(isd_list, degree):
    """
    Generate an ISD graph with each vertex having specified degree

    :param isd_list: List of isd's
    :type isd_list: list
    :param degree: The degree of isd connections
    :type degree: int

    :returns: An ISD graph
    :rtype: :class: `networkx.MultiDiGraph`
    """
    isd_graph = nx.MultiDiGraph()
    count_isds = len(isd_list)
    curr_num_edges = 0
    # Adding edges with degree chosen as degree
    max_num_edges = count_isds * degree
    if len(isd_list) < 2:
        isd_graph.add_node(MIN_ISD_NUM)
        return isd_graph
    # Adding edges in circular fashion to ensure that isd graph remains
    # connected
    for isd in range(MIN_ISD_NUM, count_isds + 1):
        neighbor_isd = isd + 1
        if isd == count_isds:
            neighbor_isd = MIN_ISD_NUM
        isd_graph.add_edge(isd, neighbor_isd)
        curr_num_edges += 2
    # Continue adding edges between ISD's of least degree till the number
    # of edges is max_num_edges
    while curr_num_edges < max_num_edges:
        isd_list_shuffle = isd_list
        # Among all the ones with least outdegree, we choose 2 randomly
        random.shuffle(isd_list_shuffle)
        num_outedges = sorted(isd_list_shuffle,
                              key=lambda node: isd_graph.degree(node))
        isd = num_outedges[0]
        neighbor_isd = num_outedges[1]
        isd_graph.add_edge(isd, neighbor_isd)
        curr_num_edges += 2
    return isd_graph


def add_random_edges(isd_graph, core_ad_dict, max_degree):
    """
    Add edges to selected ISD's to make them denser(Internet-like)
    such that no node has degree more than max_degree

    :param isd_graph: The ISD graph upon which edges will be added
    :type isd_graph: :class: `networkx.MultiDiGraph`
    :param core_ad_dict: Dict with key:isd number, value:Core AD list
    :type core_ad_dict: dict
    :param max_degree: The maximum degree an ISD can have
    :type max_degree: int
    """
    # Sorting based on number of core AD's in an ISD
    isd_sorted_list = sorted(core_ad_dict.keys(),
                             key=lambda node: len(core_ad_dict[node]))
    count_isds = len(isd_sorted_list)
    # Choosing half of the ISD's with higher core AD's to interconnect them
    denser_isds = isd_sorted_list[int(count_isds / 2):]
    print("ISD's with denser connections: {}".format(denser_isds))
    while len(denser_isds) >= 2:
        [isd, neighbor_isd] = random.sample(denser_isds, 2)
        isd_graph.add_edge(isd, neighbor_isd)
        # Break if one of the nodes has reached max_degree
        if (isd_graph.degree(isd) >= max_degree or
                isd_graph.degree(neighbor_isd) >= max_degree):
            break
    return isd_graph


def graph_to_dot(graph, dot_output_file):
    """
    Convert a networkx graph to dot file. Will work with python2 only

    :param graph: A networkx graph
    :type graph: :class: `networkx.DiGraph`
    :param dot_output_file: The dot file which will be created
    :type dot_output_file: str
    """
    try:
        from networkx import pygraphviz   # noqa
    except ImportError:
        raise ImportError('Pygraphviz is not available for python3.' +
                          'Install it for python2 instead')
    print("Generating the dot file: {}".format(dot_output_file))
    nx.write_dot(graph, dot_output_file)


def parse(brite_files, dot_output_file, min_degree, max_degree):
    """
    1. Parse a list of topology files each into a seperate ISD
    2. All the core AD's in ISD's are interconnected using some model topology

    :param brite_files: list of brite output files to be converted
    :type brite_files: list
    :param dot_output_file: Name of dot file which will be created
    :type dot_output_file: str
    :param min_degree: Minimum degree of any ISD in inter-ISD connections
    :type min_degree: int
    :param max_degree: Maximum degree of any ISD in inter-ISD connections
    :type max_degree: int

    :returns: the newly created SCION Graph.
    :rtype: :class:`networkx.DiGraph`
    """
    isd_dict = dict()
    core_ad_dict = dict()
    num_isd = MIN_ISD_NUM
    final_graph = nx.DiGraph()
    # ISD's are numbered starting from MIN_ISD_NUM
    for brite_file in brite_files:
        if not os.path.isfile(brite_file):
            logging.error(brite_file + " file missing.")
            sys.exit()
        (isd_dict[num_isd], core_ad_dict[num_isd]) = \
            _parse(brite_file, num_isd)
        final_graph = nx.union(final_graph, isd_dict[num_isd])
        num_isd += 1
    count_isds = num_isd - 1
    assert count_isds == len(brite_files)
    print("Total number of ISD's is {}".format(count_isds))
    print("Min and Max degree of connection between ISD's are {}, {}"
          .format(min_degree, max_degree))
    isd_graph = gen_base_isd_graph(list(isd_dict.keys()), min_degree)
    isd_graph = add_random_edges(isd_graph, core_ad_dict, max_degree)
    # Adding the edges to final graph using the ISD graph
    new_routing_edges = 0
    for (src_isd_id, src_core_ads) in core_ad_dict.items():
        for (dest_isd_id, dest_core_ads) in core_ad_dict.items():
            new_edges = isd_graph.number_of_edges(src_isd_id, dest_isd_id)
            all_core_ad_conn = \
                [(x, y) for x in src_core_ads for y in dest_core_ads]
            # Number of new edges is atmost the
            # number of all possible inter-ISD connections
            new_edges = min(new_edges, len(all_core_ad_conn))
            # Randomly choosing core-ad connections
            sampled_core_ad_conn = random.sample(all_core_ad_conn, new_edges)
            for (src_core_ad, dest_core_ad) in sampled_core_ad_conn:
                final_graph.add_edge(src_core_ad, dest_core_ad,
                                     label='ROUTING', color='red')
                final_graph.add_edge(dest_core_ad, src_core_ad,
                                     label='ROUTING', color='red')
                new_routing_edges += 2
    print("{} inter-ISD routing edges added".format(new_routing_edges))
    assert nx.is_connected(final_graph.to_undirected())
    if dot_output_file is not None:
        graph_to_dot(final_graph, dot_output_file)
    return final_graph


def read_topo_file(topo_file, isd_num):
    """
    Read BRITE topology file and convert it into a networkx graph

    :param topo_file: BRITE file to be converted
    :type topo_file: str
    :param isd_num: ISD Number of the graph to be generated
    :type isd_num: int

    :returns: Networkx Graph and a list containing degree of each AD
    :rvar: (`networkx.Graph`, list)
    """
    fd = open(topo_file, 'r')
    original_graph = nx.Graph()
    num_outedges = list()
    nodes_count = 0
    edges_count = 0
    for line in fd:
        values = line.split(" ")
        if nodes_count > 0:
            nodes_count -= 1
            values = line.split("\t")
            ad_id = values[0]
            isd_ad_id = ISD_AD_ID_DIVISOR.join([str(isd_num), ad_id])
            original_graph.add_node(isd_ad_id, is_core=False)
            num_outedges.append((isd_ad_id, int(values[3])))
        if edges_count > 0:
            edges_count -= 1
            values = line.split("\t")
            source_isd_ad_id = ISD_AD_ID_DIVISOR.join([str(isd_num),
                                                      values[1]])
            dest_isd_ad_id = ISD_AD_ID_DIVISOR.join([str(isd_num),
                                                     values[2]])
            original_graph.add_edge(source_isd_ad_id, dest_isd_ad_id)
        if values[0] == "Nodes:":
            nodes_count = int(values[2])
        if values[0] == "Edges:":
            edges_count = int(values[2])
    return original_graph, num_outedges


def _parse(topo_file, isd_num):
    """
    Parse a topo_file into a SCION ISD numbered - isd_num

    :param topo_file: A BRITE output file to be converted
    :type topo_file: str
    :param isd_num: ISD Number of the graph to be generated
    :type isd_num: int

    :returns: the created Graph along with a list of core ad nodes
    :rtype: (`networkx.DiGraph`, list)
    """
    (original_graph, num_outedges) = read_topo_file(topo_file, isd_num)
    num_core_ads = min(MAX_CORE_ADS, int(len(original_graph.nodes()) / 10))
    num_outedges = sorted(num_outedges, key=lambda tup: tup[1],
                          reverse=True)
    core_ads = [(i[0]) for i in num_outedges[:num_core_ads]]
    core_ad_graph = original_graph.subgraph(core_ads)

    # Ensuring that core ad graph is connected
    if not nx.is_connected(core_ad_graph):
        # If not connected, the new core ad graph is formed from the largest
        # connected component. Nodes are added to it from its neighbors to make
        # size of core_ad_graph = num_core_ads
        graphs = list(nx.connected_component_subgraphs(core_ad_graph))
        graphs = sorted(graphs, key=lambda graph: len(graph.nodes()),
                        reverse=True)
        core_ad_graph = graphs[0]
        core_ads = core_ad_graph.nodes()
        num_extra_nodes = num_core_ads - len(core_ads)
        neighbor_nodes = set()
        for neighbor in [original_graph.neighbors(node)
                         for node in core_ad_graph]:
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
            elif visited.get(neighbor) is None:
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
    assert 2 * len(original_graph.edges()) == len(final_graph.edges())

    print("ISD {} has {} AS's".format(isd_num, len(original_graph.nodes())))
    print("Core AD's are:")
    print(core_ad_graph.nodes())
    return final_graph, core_ad_graph.nodes()


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
        if cert_issuer is not None:
            topo_dict[isd_ad_id]["cert_issuer"] = cert_issuer

    with open(DEFAULT_ADCONFIGURATIONS_FILE, 'w') as topo_fh:
        json.dump(topo_dict, topo_fh, sort_keys=True, indent=4)


def main():
    """
    Main function
    """
    if len(sys.argv) < 2:
        logging.error("run: %s -h for help", sys.argv[0])
        sys.exit()

    parser = argparse.ArgumentParser(description='SCION Topology generator')
    parser.add_argument('-d', '--dir',
                        action='store',
                        dest='from_directory',
                        help="Convert each files in the specified directory \
                              into an isd")
    parser.add_argument('-f', '--files', '--file',
                        action='store',
                        dest='collection',
                        nargs='+',
                        help="Convert files into respective isd's")
    parser.add_argument('-c', '--degree',
                        action='store',
                        default=[3, 5],
                        dest='degree',
                        nargs=2,
                        help="Set the min and max degree of connections \
                              between core AD's of different ISD's")
    parser.add_argument('-o', '--out',
                        action='store',
                        default=None,
                        dest='dot_output_file',
                        help="Generates a dot output file(pygraphviz does not \
                              work in python 3.x, works only in python 2.x).")
    results = parser.parse_args()
    if not (results.from_directory or results.collection):
        parser.error('No files provided. Add -d or -f as argument')
    if results.from_directory is not None:
        brite_files = read_from_dir(results.from_directory)
    else:
        brite_files = results.collection
    scion_graph = parse(brite_files, results.dot_output_file,
                        int(results.degree[0]), int(results.degree[1]))
    json_convert(scion_graph)

if __name__ == "__main__":
    main()
