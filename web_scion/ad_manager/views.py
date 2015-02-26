from django.shortcuts import render

from lib.config import Config
from lib.topology import Topology
from web_scion.settings import SCION_DIR


def index(request):
    config_file = SCION_DIR + "/topology/ISD1/configurations/ISD:1-AD:11-V:0.conf"
    topo_file = SCION_DIR + "/topology/ISD1/topologies/ISD:1-AD:11-V:0.json"

    config = Config(config_file)
    topology = Topology(topo_file)

    routers = topology.parent_edge_routers + \
              topology.child_edge_routers + \
              topology.peer_edge_routers

    return render(request, 'index.html', {'config': config,
                                          'topology': topology,
                                          'routers': routers})
