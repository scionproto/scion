from django.http import JsonResponse
from django.shortcuts import render

from django.conf import settings
from django.views.generic import ListView, DetailView
from ad_manager.models import AD, ISD
from lib.config import Config
from lib.topology import Topology


class ISDListView(ListView):
    model = ISD


class ISDDetailView(DetailView):
    model = ISD


class ADDetailView(DetailView):
    model = AD

    def get_context_data(self, **kwargs):
        context = super(ADDetailView, self).get_context_data(**kwargs)
        ad = context['object']
        context['routers'] = ad.routerweb_set.all()
        context['path_servers'] = ad.pathserverweb_set.all()
        context['certificate_servers'] = ad.certificateserverweb_set.all()
        context['beacon_servers'] = ad.beaconserverweb_set.all()
        return context


def index(request):
    config = Config(settings.CONFIG_FILE)
    topology = Topology(settings.TOPO_FILE)


    routers = topology.parent_edge_routers + \
              topology.child_edge_routers + \
              topology.peer_edge_routers + \
              topology.routing_edge_routers

    routers = sorted(routers, key=lambda r: str(r.addr))

    return render(request, 'ad_manager/ad_detail.html', {'config': config,
                                                         'topology': topology,
                                                         'routers': routers})


def get_ad_status(request, pk):
    ad = AD.objects.get(id=pk)
    ad_info = ad.query_ad_status()
    return JsonResponse({'data': ad_info})

