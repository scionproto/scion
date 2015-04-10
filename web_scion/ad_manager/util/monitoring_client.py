import base64
import hashlib
import os
import xmlrpc.client
from ad_management.common import (get_monitoring_server, response_failure,
    response_success, is_success, get_success_data)


def get_ad_info(isd_id, ad_id, md_host):
    s = get_monitoring_server(md_host)
    try:
        ad_info = s.get_ad_info(isd_id, ad_id)
        return ad_info
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return response_failure('Query failed', str(ex))


def get_topology(isd_id, ad_id, md_host):
    s = get_monitoring_server(md_host)
    try:
        topo_response = s.get_topology(isd_id, ad_id)
        if is_success(topo_response):
            return get_success_data(topo_response)
        else:
            return None
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        # TODO replace with response_failure?
        return None


def send_update(isd_id, ad_id, md_host, arch_path):
    with open(arch_path, 'rb') as update_fh:
        raw_data = update_fh.read()

    s = get_monitoring_server(md_host)

    data_digest = hashlib.sha1(raw_data).hexdigest()
    base64_data = str(base64.b64encode(raw_data), 'utf-8')

    data_dict = {'data': base64_data, 'digest': data_digest,
                 'name': os.path.basename(arch_path)}
    try:
        if not s.send_update(isd_id, ad_id, data_dict):
            return 'CANNOT UPDATE'
        return response_success('OK')
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return response_failure()
