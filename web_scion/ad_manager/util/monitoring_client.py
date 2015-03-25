import base64
import hashlib
import xmlrpc.client
from daemon_monitor.common import get_monitoring_server


def get_ad_info(isd_id, ad_id):
    s = get_monitoring_server()
    try:
        ad_info = s.get_ad_info(isd_id, ad_id)
        return ad_info
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return None


def get_topology(isd_id, ad_id):
    s = get_monitoring_server()
    try:
        topo = s.get_topology(isd_id, ad_id)
        return topo
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return None


def send_update(isd_id, ad_id):
    update_dir = '../dist/'
    arch_name = 'scion-0.1.0.tar.gz'
    with open(update_dir + arch_name, 'rb') as update_fh:
        raw_data = update_fh.read()

    s = get_monitoring_server()

    data_digest = hashlib.sha1(raw_data).hexdigest()
    base64_data = str(base64.b64encode(raw_data), 'utf-8')

    data_dict = {'data': base64_data, 'digest': data_digest, 'name': arch_name}
    try:
        if not s.send_update(isd_id, ad_id, data_dict):
            return 'CANNOT UPDATE'
        return 'OK'
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return None