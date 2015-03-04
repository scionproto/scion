from django.shortcuts import render

from django.conf import settings
from lib.config import Config
from lib.topology import Topology


def index(request):
    config = Config(settings.CONFIG_FILE)
    topology = Topology(settings.TOPO_FILE)

    routers = topology.parent_edge_routers + \
              topology.child_edge_routers + \
              topology.peer_edge_routers + \
              topology.routing_edge_routers

    routers = sorted(routers, key=lambda r: str(r.addr))

    return render(request, 'index.html', {'config': config,
                                          'topology': topology,
                                          'routers': routers})
