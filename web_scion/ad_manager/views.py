# Stdlib
import json
import os
import tempfile
import time
from shutil import rmtree

# External packages
import dictdiffer
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect, get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.views.generic import ListView, DetailView, FormView

# SCION
from guardian.shortcuts import assign_perm
from ad_management.common import (
    get_failure_errors,
    get_success_data,
    is_success,
    PACKAGE_DIR_PATH,
    response_failure,
)
from ad_management.packaging import prepare_package
from ad_manager.forms import (
    ConnectionRequestForm,
    NewLinkForm,
    PackageVersionSelectForm,
)
from ad_manager.models import AD, ISD, PackageVersion, ConnectionRequest
from ad_manager.util import monitoring_client
from ad_manager.util.ad_connect import (
    create_new_ad_files,
    find_last_router,
    link_ads,
)
from ad_manager.util.errors import HttpResponseUnavailable
from lib.defines import BEACON_SERVICE
from lib.topology import Topology
from lib.util import write_file
from topology.generator import ConfigGenerator


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
        context['routers'] = ad.routerweb_set.select_related()
        context['path_servers'] = ad.pathserverweb_set.all()
        context['certificate_servers'] = ad.certificateserverweb_set.all()
        context['beacon_servers'] = ad.beaconserverweb_set.all()
        context['dns_servers'] = ad.dnsserverweb_set.all()

        # Sort by name numerically
        lists_to_sort = ['routers', 'path_servers',
                         'certificate_servers', 'beacon_servers',
                         'dns_servers']
        for list_name in lists_to_sort:
            context[list_name] = sorted(
                context[list_name],
                key=lambda el: int(el.name) if el.name is not None else -1
            )

        # Update tab
        context['choose_version_form'] = PackageVersionSelectForm()

        # Connection requests tab
        context['received_requests'] = ad.received_requests.all()

        # Permissions
        context['user_has_perm'] = self.request.user.has_perm('change_ad', ad)
        return context


def get_ad_status(request, pk):
    """
    Send a query to the corresponding monitoring daemon, asking for the status
    of AD servers.
    """
    ad = get_object_or_404(AD, id=pk)
    ad_info_list_response = ad.query_ad_status()
    if is_success(ad_info_list_response):
        return JsonResponse({'data': get_success_data(ad_info_list_response)})
    else:
        error = get_failure_errors(ad_info_list_response)
        return HttpResponseUnavailable(error)


def get_group_master(request, pk):
    """
    Get the server group master (the one, who holds the lock in ZK).
    """
    ad = get_object_or_404(AD, id=pk)
    server_type = request.GET.get('server_type', '')
    if server_type != BEACON_SERVICE:
        return HttpResponseNotFound('Invalid server type')

    response = monitoring_client.get_master_id(ad.md_host, ad.isd.id, ad.id,
                                               server_type)
    if is_success(response):
        master_id = get_success_data(response)
        return JsonResponse({'server_type': server_type,
                             'server_id': master_id})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


def _get_changes(current_topology, remote_topology):
    diff_changes = list(dictdiffer.diff(current_topology, remote_topology))
    processed_changes = []
    for change in diff_changes:
        change_type, element, changes = list(change)
        change = 'Local -> remote: {}, element: {}, changes: {}'.format(
            change_type, str(element), str(changes)
        )
        processed_changes.append(change)
    return processed_changes


def compare_remote_topology(request, pk):
    """
    Retrieve the remote topology and compare it with the one stored in the
    database.
    """
    ad = get_object_or_404(AD, id=pk)
    remote_topology = ad.get_remote_topology()
    if not remote_topology:
        return HttpResponseUnavailable('Cannot get the topology')

    current_topology = ad.generate_topology_dict()

    changes = _get_changes(current_topology, remote_topology)
    if changes:
        state = 'CHANGED'
    else:
        state = 'OK'
    return JsonResponse({'state': state, 'changes': changes})


@require_POST
@transaction.atomic
def update_topology(request, pk):
    """
    Update topology action: either push or pull the topology.
    """
    ad = get_object_or_404(AD, id=pk)
    _check_user_permissions(request, ad)

    ad_page = reverse('ad_detail', args=[ad.id])
    if '_pull_topology' in request.POST:
        return _update_from_remote_topology(request, ad)
    elif '_push_topology' in request.POST:
        return _push_local_topology(request, ad)
    return redirect(ad_page)


def _push_local_topology(request, ad):
    local_topo = ad.generate_topology_dict()
    # TODO move to model?
    response = monitoring_client.push_topology(ad.md_host, str(ad.isd.id),
                                               str(ad.id), local_topo)
    topology_tag = 'topology'
    if is_success(response):
        messages.success(request, 'OK', extra_tags=topology_tag)
    else:
        messages.error(request, get_failure_errors(response),
                       extra_tags=topology_tag)
    # Wait until supervisor is restarting
    time.sleep(1)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def _update_from_remote_topology(request, ad):
    """
    Atomically retrieve the remote topology and update the stored topology
    for the given AD.
    """
    remote_topology_dict = ad.get_remote_topology()
    remote_topology = Topology.from_dict(remote_topology_dict)
    ad.fill_from_topology(remote_topology, clear=True)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def _send_update(request, ad, package):
    """
    Send the update package and initiate the update process.
    """
    # TODO move to model?
    if package.exists():
        result = monitoring_client.send_update(ad.md_host, ad.isd_id, ad.id,
                                               package.filepath)
    else:
        result = response_failure('Package not found')

    update_tag = 'updates'
    if is_success(result):
        messages.success(request, 'Update started', extra_tags=update_tag)
    else:
        error = get_failure_errors(result)
        messages.error(request, error, extra_tags=update_tag)
    return redirect(reverse('ad_detail_updates', args=[ad.id]))


def _download_update(request, package):
    """
    Download the update package straight from the web panel.
    """
    if not package.exists():
        return HttpResponseNotFound('Package not found')
    return _download_file_response(package.filepath)


@require_POST
def software_update_action(request, pk):
    ad = get_object_or_404(AD, id=pk)
    _check_user_permissions(request, ad)

    ad_page = reverse('ad_detail', args=[ad.id])
    form = PackageVersionSelectForm(request.POST)
    if form.is_valid():
        package = form.cleaned_data['selected_version']
        if '_download_update' in request.POST:
            return _download_update(request, package)
        elif '_install_update' in request.POST:
            return _send_update(request, ad, package)
    return redirect(ad_page)


@require_POST
def refresh_versions(request, pk):
    """
    Refresh version choice form element.
    """
    ad = get_object_or_404(AD, id=pk)
    PackageVersion.discover_packages()
    updates_page = reverse('ad_detail_updates', args=[ad.id])
    return redirect(updates_page)


def _download_file_response(file_path, file_name=None, content_type=None):
    if file_name is None:
        file_name = os.path.basename(file_path)
    if content_type is None:
        content_type = 'application/x-gzip'
    with open(file_path, 'rb') as file_fh:
        response = HttpResponse(file_fh.read(), content_type=content_type)
        response['Content-Length'] = file_fh.tell()
    response['Content-Disposition'] = ('attachment; '
                                       'filename={}'.format(file_name))
    return response


def _connect_new_ad(request, ad):
    # TODO(rev112): Remove or move to approve_request()
    topology_page = reverse('ad_detail_topology', args=[ad.id])

    # Chech that remote topology exists
    remote_topology = ad.get_remote_topology()
    topology_tag = 'topology'
    if not remote_topology:
        messages.error(request, 'Cannot get the remote topology',
                       extra_tags=topology_tag)
        return redirect(topology_page)

    # Find if there are differences
    local_topology = ad.generate_topology_dict()
    if _get_changes(local_topology, remote_topology):
        messages.error(request, 'Topologies are inconsistent, '
                                'please push or pull the topology',
                       extra_tags=topology_tag)
        return redirect(topology_page)


def _check_user_permissions(request, ad):
    # TODO(rev112) decorator?
    if not request.user.has_perm('change_ad', ad):
        raise PermissionDenied()


@require_POST
def control_process(request, pk, proc_id):
    """
    Send a control command to an AD element instance.
    """
    ad = get_object_or_404(AD, id=pk)
    _check_user_permissions(request, ad)

    ad_elements = ad.get_all_element_ids()
    if proc_id not in ad_elements:
        return HttpResponseNotFound('Element not found')

    if '_start_process' in request.POST:
        command = 'START'
    elif '_stop_process' in request.POST:
        command = 'STOP'
    else:
        return HttpResponseNotFound('Command not found')

    response = monitoring_client.control_process(ad.md_host, ad.isd.id, ad.id,
                                                 proc_id, command)
    if is_success(response):
        return JsonResponse({'status': True})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


def read_log(request, pk, proc_id):
    # FIXME(rev112): minor duplication, see control_process()
    ad = get_object_or_404(AD, id=pk)
    _check_user_permissions(request, ad)

    ad_elements = ad.get_all_element_ids()
    if proc_id not in ad_elements:
        return HttpResponseNotFound('Element not found')
    proc_id = ad.get_full_process_name(proc_id)

    response = monitoring_client.read_log(ad.md_host, proc_id)
    if is_success(response):
        log_data = get_success_data(response)[0]
        if '\n' in log_data:
            log_data = log_data[log_data.index('\n') + 1:]
        return JsonResponse({'data': log_data})
    else:
        return HttpResponseUnavailable(get_failure_errors(response))


class ConnectionRequestView(FormView):
    form_class = ConnectionRequestForm
    template_name = 'ad_manager/new_connection_request.html'
    success_url = ''

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def _get_ad(self):
        return get_object_or_404(AD, id=self.kwargs['pk'])

    def form_valid(self, form):
        if not self.request.user.is_authenticated():
            return HttpResponseForbidden('Authentication required')

        connect_to = self._get_ad()
        form.instance.connect_to = connect_to
        form.instance.created_by = self.request.user
        form.save()

        con_request = form.instance
        con_request.status = 'SENT'

        if not con_request.router_public_ip:
            # Public = Bound
            con_request.router_public_ip = con_request.router_bound_ip
            con_request.router_public_port = con_request.router_bound_port
        con_request.save()

        self.success_url = reverse('sent_requests')
        if connect_to.is_open:
            # Create new AD
            approve_request(connect_to, con_request)

        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data


class NewLinkView(FormView):
    form_class = NewLinkForm
    template_name = 'ad_manager/new_link.html'
    success_url = ''

    def _get_ad(self):
        return get_object_or_404(AD, id=self.kwargs['pk'])

    def dispatch(self, request, *args, **kwargs):
        ad = self._get_ad()
        _check_user_permissions(request, ad)
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['from_ad'] = self._get_ad()
        return kwargs

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data

    def form_valid(self, form):
        this_ad = self._get_ad()
        from_ad = this_ad
        to_ad = form.cleaned_data['end_point']
        link_type = form.cleaned_data['link_type']

        if link_type == 'PARENT':
            from_ad, to_ad = to_ad, from_ad

        if link_type in ['CHILD', 'PARENT']:
            link_type = 'PARENT_CHILD'

        with transaction.atomic():
            link_ads(from_ad, to_ad, link_type)

        self.success_url = reverse('ad_detail', args=[this_ad.id])
        return super().form_valid(form)


def download_approved_package(request, req_id):
    ad_request = get_object_or_404(ConnectionRequest, id=req_id)
    _check_user_permissions(request, ad_request.new_ad)
    if not ad_request.is_approved():
        raise PermissionDenied('Request is not approved')
    return _download_file_response(ad_request.package_path)


def approve_request(ad, ad_request):

    # Create the new AD
    new_id = AD.objects.latest('id').id + 1
    new_ad = AD.objects.create(id=new_id, isd=ad.isd,
                               md_host=ad_request.router_public_ip)
    parent_topo_dict = ad.generate_topology_dict()

    with tempfile.TemporaryDirectory() as temp_dir:
        new_topo_dict, parent_topo_dict = create_new_ad_files(parent_topo_dict,
                                                              new_ad.isd.id,
                                                              new_ad.id,
                                                              out_dir=temp_dir)

        # Adjust router ips/ports
        if ad_request.router_public_ip is None:
            ad_request.router_public_ip = ad_request.router_bound_ip

        if ad_request.router_public_port is None:
            ad_request.router_public_port = ad_request.router_bound_port

        _, new_topo_router = find_last_router(new_topo_dict)
        new_topo_router['Interface']['Addr'] = ad_request.router_bound_ip
        new_topo_router['Interface']['UdpPort'] = ad_request.router_bound_port

        _, parent_topo_router = find_last_router(parent_topo_dict)
        parent_router_if = parent_topo_router['Interface']
        parent_router_if['ToAddr'] = ad_request.router_public_ip
        parent_router_if['UdpPort'] = ad_request.router_public_port

        new_topo = Topology.from_dict(new_topo_dict)
        parent_topo = Topology.from_dict(parent_topo_dict)

        new_ad.fill_from_topology(new_topo, clear=True)
        ad.fill_from_topology(parent_topo, clear=True)

        # Update the new topology on disk:
        # Write new config files to disk, regenerate everything else
        # FIXME(rev112): minor duplication, see ad_connect.create_new_ad_files()
        gen = ConfigGenerator(out_dir=temp_dir)
        new_topo_path = gen.path_dict(new_ad.isd.id, new_ad.id)['topo_file_abs']
        write_file(new_topo_path, json.dumps(new_topo_dict,
                                             sort_keys=4, indent=4))
        gen.write_derivatives(new_topo_dict)

        # Resulting package will be stored here
        package_dir = os.path.join(PACKAGE_DIR_PATH, 'AD' + str(new_ad))
        if os.path.exists(package_dir):
            rmtree(package_dir)
        os.makedirs(package_dir)

        # Prepare package
        package_name = 'scion_package_AD{}-{}'.format(new_ad.isd, new_ad.id)
        config_dirs = [os.path.join(temp_dir, x) for x in os.listdir(temp_dir)]
        ad_request.package_path = prepare_package(out_dir=package_dir,
                                                  config_paths=config_dirs,
                                                  package_name=package_name)
        ad_request.new_ad = new_ad
        ad_request.status = 'APPROVED'
        ad_request.save()

        # Give permissions to the user
        request_creator = ad_request.created_by
        assign_perm('change_ad', request_creator, new_ad)

        new_ad.save()
        ad.save()


@transaction.atomic
@require_POST
def request_action(request, req_id):
    """
    Approve or decline the sent connection request.
    """
    ad_request = get_object_or_404(ConnectionRequest, id=req_id)
    ad = ad_request.connect_to
    _check_user_permissions(request, ad)

    if '_approve_request' in request.POST:
        if not ad_request.is_approved():
            approve_request(ad, ad_request)
    elif '_decline_request' in request.POST:
        ad_request.status = 'DECLINED'
    else:
        return HttpResponseNotFound('Action not found')
    ad_request.save()
    return redirect(reverse('ad_connection_requests', args=[ad.id]))


@login_required
def list_sent_requests(request):
    """
    List requests, sent by the current user.
    """
    user = request.user
    sent_requests = user.connectionrequest_set.all()
    return render(request, 'ad_manager/sent_requests.html',
                  {'sent_requests': sent_requests})


def network_view(request):
    ad_graph_tmp = []
    ad_index = {}
    ad_index_rev = {}
    ads = AD.objects.all()
    # TODO(rev112) check optimizations
    ads = ads.prefetch_related('routerweb_set__neighbor_ad')
    for i, ad in enumerate(ads):
        ad_index[i] = ad
        ad_index_rev[ad] = i
        ad_routers = ad.routerweb_set.all()
        ad_graph_tmp.append([r.neighbor_ad for r in ad_routers])

    # Rewrite neighbors
    ad_graph = []
    for neighbors in ad_graph_tmp:
        ad_graph.append([ad_index_rev[n] for n in neighbors])

    graph = {'nodes': [], 'links': []}
    for index, neighbors in enumerate(ad_graph):
        ad = ad_index[index]
        graph['nodes'].append({
            'name': 'AD {}-{}'.format(ad.isd_id, ad.id),
            'group': ad.isd_id,
            'url': ad.get_absolute_url(),
            'core': int(ad.is_core_ad),
        })
        for n in neighbors:
            if index < n:
                graph['links'].append({
                    'source': index,
                    'target': n,
                    'value': 1,
                })

    return render(request, 'ad_manager/network_view.html', {'data': graph})
