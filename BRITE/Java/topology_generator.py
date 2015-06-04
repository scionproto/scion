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

outputGraph = False

def parse(topo_file):
    fd = open(topo_file, 'r')
    parsingNodes = False
    parsingEdges = False

    G = nx.Graph()
    for line in fd:
        values = line.split(" ")
        
        if parsingNodes:
            if line == "\n":
                parsingNodes = False
            else:
                values = line.split("\t")
                G.add_node(int(values[0]))

        if parsingEdges:
            if line == "\n":
                parsingEdges = False
            else:
                values = line.split("\t")
                G.add_edge(int(values[1]), int(values[2]))

        if values[0] == "Nodes:":
            parsingNodes = True
        elif values[0] == "Edges:":
            parsingEdges = True


    # print(G.nodes(), G.edges())
    if outputGraph:
        # convert to a graphviz agraph
        A=nx.to_agraph(G)

        # write to dot file
        A.write('topo1.dot')


def main():
    if len(sys.argv) != 2:
        logging.error("run: %s topo_file ",
                      sys.argv[0])
        sys.exit()

    parse(sys.argv[1])

if __name__ == "__main__":
    main()