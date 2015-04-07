import json
import os
import tempfile
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.shortcuts import redirect
from django.utils.encoding import smart_str
from django.views.generic import ListView, DetailView
from ad_manager.models import AD, ISD
from ad_manager.util import monitoring_client
from daemon_monitor.common import is_success, get_success_data, \
    ARCHIVE_DIST_PATH
from lib.topology import Topology

ARCH_NAME = 'scion-0.1.0.tar.gz'


class ISDListView(ListView):
    model = ISD


class ISDDetailView(DetailView):
    model = ISD


class ADDetailView(DetailView):
    model = AD

    def get_context_data(self, **kwargs):
        context = super(ADDetailView, self).get_context_data(**kwargs)
        ad = context['object']
        context['routers'] = ad.routerweb_set.select_related().all()
        context['path_servers'] = ad.pathserverweb_set.all()
        context['certificate_servers'] = ad.certificateserverweb_set.all()
        context['beacon_servers'] = ad.beaconserverweb_set.all()
        return context


def get_ad_status(request, pk):
    ad = AD.objects.get(id=pk)
    ad_info_list_response = ad.query_ad_status()
    if is_success(ad_info_list_response):
        return JsonResponse({'data': get_success_data(ad_info_list_response)})
    else:
        return JsonResponse({})


def compare_remote_topology(request, pk):
    # TODO move to model?
    def addr_key_sort(k):
        return k['Addr']

    ad = AD.objects.get(id=pk)
    remote_topology = ad.get_remote_topology()
    if not remote_topology:
        return JsonResponse({'status': 'FAIL'})

    current_topology = ad.generate_topology_dict()
    changes = []

    keys = ['ADID', 'ISDID', 'Core']
    for key in keys:
        if remote_topology[key] != current_topology[key]:
            changes.append('"{}" values differ'.format(key))

    element_fields = {'PathServers': ['Addr'],
                      'CertificateServers': ['Addr'],
                      'BeaconServers': ['Addr'],
                      'EdgeRouters': ['Addr', ('Interface', ['NeighborAD',
                                                             'NeighborISD',
                                                             'NeighborType'])]
                      }
    for server_type in element_fields.keys():
        remote_servers = sorted(remote_topology[server_type].values(),
                                key=addr_key_sort)
        current_servers = sorted(current_topology[server_type].values(),
                                 key=addr_key_sort)
        if len(remote_servers) != len(current_servers):
            changes.append('Different number of "{}" servers'.format(server_type))
            continue
        for rs, cs in zip(remote_servers, current_servers):
            current_fields = element_fields[server_type]
            for key in current_fields:
                if isinstance(key, str) and rs[key] != cs[key]:
                    changes.append('"{}" values differ for some {}'
                                   .format(key, server_type))
                    continue
                if isinstance(key, tuple):
                    field_name, nested_fields = key
                    for field in nested_fields:
                        if rs[field_name][field] != cs[field_name][field]:
                            changes.append('"{}:{}" values differ for some {}'
                                           .format(field_name, field,
                                                   server_type))
    if changes:
        status = 'CHANGED'
    else:
        status = 'OK'
    return JsonResponse({'status': status, 'changes': changes})


@transaction.atomic
def update_from_remote_topology(request, pk):
    ad = AD.objects.get(id=pk)
    remote_topology_dict = ad.get_remote_topology()
    # Write topology to a temp file
    with tempfile.NamedTemporaryFile(mode='w') as tmp:
        json.dump(remote_topology_dict, tmp)
        tmp.flush()
        remote_topology = Topology(tmp.name)
    ad.fill_from_topology(remote_topology, clear=True)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def send_update(request, pk):
    # TODO move to model?
    ad = AD.objects.get(id=pk)
    arch_path = os.path.join(ARCHIVE_DIST_PATH, ARCH_NAME)
    result = monitoring_client.send_update(ad.isd_id, ad.id,
                                           ad.get_monitoring_daemon_host(),
                                           arch_path)
    return JsonResponse({'status': result})


def download_update(request, pk):
    arch_path = os.path.join(ARCHIVE_DIST_PATH, ARCH_NAME)
    with open(arch_path, 'rb') as arch_fh:
        response = HttpResponse(arch_fh.read(),
                                content_type='application/x-gzip')
        response['Content-Length'] = arch_fh.tell()
    response['Content-Disposition'] = ('attachment; '
                                       'filename={}'.format(ARCH_NAME))
    return response


