# Stdlib
import json
import tempfile

# External packages
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect
from django.views.generic import ListView, DetailView

# SCION
from ad_management.common import (
    get_success_data,
    is_success,
    response_failure,
    get_failure_errors
)
from ad_manager.forms import PackageVersionSelectForm
from ad_manager.models import AD, ISD, PackageVersion
from ad_manager.util import monitoring_client
from lib.topology import Topology


class ISDListView(ListView):
    model = ISD


class ISDDetailView(DetailView):
    model = ISD


class ADDetailView(DetailView):
    model = AD

    def get_context_data(self, **kwargs):
        """
        Populate 'context' dictionary with the required objects
        """
        context = super(ADDetailView, self).get_context_data(**kwargs)
        ad = context['object']
        # Status tab
        context['routers'] = ad.routerweb_set.select_related().all()
        context['path_servers'] = ad.pathserverweb_set.all()
        context['certificate_servers'] = ad.certificateserverweb_set.all()
        context['beacon_servers'] = ad.beaconserverweb_set.all()

        # Update tab
        context['choose_version_form'] = PackageVersionSelectForm()

        return context


def get_ad_status(request, pk):
    """
    Send a query to the corresponding monitoring daemon, asking for the status
    of AD servers.
    """
    ad = AD.objects.get(id=pk)
    ad_info_list_response = ad.query_ad_status()
    if is_success(ad_info_list_response):
        return JsonResponse({'data': get_success_data(ad_info_list_response)})
    else:
        return JsonResponse({})


def compare_remote_topology(request, pk):
    """
    Retrieve the remote topology and compare it with the one stored in the
    database.
    """
    ad = AD.objects.get(id=pk)
    remote_topology = ad.get_remote_topology()
    if not remote_topology:
        return JsonResponse({'status': 'FAIL',
                             'errors': ['Cannot get the remote topology']})

    current_topology = ad.generate_topology_dict()
    changes = []

    keys = ['ADID', 'ISDID', 'Core']
    for key in keys:
        if remote_topology[key] != current_topology[key]:
            changes.append('"{}" values differ'.format(key))

    # Values must match for the keys provided here
    element_fields = {'PathServers': ['Addr'],
                      'CertificateServers': ['Addr'],
                      'BeaconServers': ['Addr'],
                      'EdgeRouters': ['Addr', ('Interface', ['NeighborAD',
                                                             'NeighborISD',
                                                             'NeighborType'])]
                      }
    addr_key_sort = lambda k: k['Addr']
    for server_type in element_fields.keys():
        remote_servers = sorted(remote_topology[server_type].values(),
                                key=addr_key_sort)
        current_servers = sorted(current_topology[server_type].values(),
                                 key=addr_key_sort)
        if len(remote_servers) != len(current_servers):
            changes.append(
                'Different number of "{}" servers'.format(server_type)
            )
            continue
        for rs, cs in zip(remote_servers, current_servers):
            current_fields = element_fields[server_type]
            for key in current_fields:
                if isinstance(key, str) and rs[key] != cs[key]:
                    changes.append('"{}" values differ for some {}'
                                   .format(key, server_type))
                    continue
                if isinstance(key, tuple):
                    # Compare nested dictionaries (for 'EdgeRouters')
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
    """
    Atomically retrieve the remote topology and update the stored topology
    for the given AD.
    """
    ad = AD.objects.get(id=pk)
    remote_topology_dict = ad.get_remote_topology()
    # Write the retrieved topology to a temp file
    with tempfile.NamedTemporaryFile(mode='w') as tmp:
        json.dump(remote_topology_dict, tmp)
        tmp.flush()
        remote_topology = Topology.from_file(tmp.name)
    ad.fill_from_topology(remote_topology, clear=True)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def _send_update(request, ad, package):
    """
    Send the update package and initiate the update process.
    """
    # TODO move to model?
    if package.exists():
        result = monitoring_client.send_update(ad.isd_id, ad.id,
                                               ad.get_monitoring_daemon_host(),
                                               package.filepath)
    else:
        result = response_failure('Package not found')

    if is_success(result):
        messages.success(request, 'Update started')
    else:
        error = get_failure_errors(result)
        messages.error(request, error)
    return redirect(reverse('ad_detail_updates', args=[ad.id]))


def _download_update(request, ad, package):
    """
    Download the update package straight from the web panel.
    """

    if not package.exists():
        return HttpResponseNotFound('Package not found')

    with open(package.filepath, 'rb') as arch_fh:
        response = HttpResponse(arch_fh.read(),
                                content_type='application/x-gzip')
        response['Content-Length'] = arch_fh.tell()
    response['Content-Disposition'] = ('attachment; '
                                       'filename={}'.format(package.name))
    return response


def update_action(request, pk):
    ad = AD.objects.get(id=pk)
    ad_page = reverse('ad_detail', args=[ad.id])
    if request.method != 'POST':
        return redirect(ad_page)

    form = PackageVersionSelectForm(request.POST)
    if form.is_valid():
        package = form.cleaned_data['selected_version']
        if '_download_update' in request.POST:
            return _download_update(request, ad, package)
        if '_install_update' in request.POST:
            return _send_update(request, ad, package)
    return redirect(ad_page)


def refresh_versions(request, pk):
    PackageVersion.discover_packages()
    return redirect(reverse('ad_detail_updates', args=[pk]))
