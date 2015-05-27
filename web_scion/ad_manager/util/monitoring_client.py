# Stdlib
import base64
import hashlib
import os
import xmlrpc.client

# SCION
from ad_management.common import get_monitoring_server, response_failure


def get_ad_info(isd_id, ad_id, md_host):
    """
    get_ad_info XML-RPC call to the management daemon
    """
    s = get_monitoring_server(md_host)
    try:
        ad_info = s.get_ad_info(isd_id, ad_id)
        return ad_info
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return response_failure('Query failed', str(ex))


def get_topology(isd_id, ad_id, md_host):
    """
    get_topology XML-RPC call to the management daemon
    """
    s = get_monitoring_server(md_host)
    try:
        topo_response = s.get_topology(isd_id, ad_id)
        return topo_response
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return response_failure('Cannot get the topology', str(ex))


def send_update(isd_id, ad_id, md_host, arch_path):
    """
    send_update XML-RPC call to the management daemon
    """

    with open(arch_path, 'rb') as update_fh:
        raw_data = update_fh.read()

    s = get_monitoring_server(md_host)
    data_digest = hashlib.sha1(raw_data).hexdigest()
    base64_data = str(base64.b64encode(raw_data), 'utf-8')

    data_dict = {'data': base64_data, 'digest': data_digest,
                 'name': os.path.basename(arch_path)}
    try:
        update_response = s.send_update(isd_id, ad_id, data_dict)
        return update_response
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return response_failure('Cannot send the update', str(ex))
