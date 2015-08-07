# Stdlib
import base64
import hashlib
import os
import xmlrpc.client

# SCION
from ad_management.util import get_monitoring_server, response_failure


def run_remote(func):
    """
    Decorator which prepares the monitoring server and wraps errors.
    """

    def wrapper(md_host, *args, **kwargs):
        s = get_monitoring_server(md_host)
        try:
            return func(s, *args, **kwargs)
        except ConnectionRefusedError as ex:
            return response_failure(['Cannot connect to the daemon', str(ex)])
        except xmlrpc.client.Error as ex:
            return response_failure(['Query failed', str(ex)])

    return wrapper


@run_remote
def get_ad_info(s, isd_id, ad_id):
    """
    get_ad_info XML-RPC call to the management daemon
    """
    return s.get_ad_info(str(isd_id), str(ad_id))


@run_remote
def get_topology(s, isd_id, ad_id):
    """
    get_topology XML-RPC call to the management daemon
    """
    return s.get_topology(str(isd_id), str(ad_id))


@run_remote
def push_topology(s, isd_id, ad_id, topology):
    """
    get_topology XML-RPC call to the management daemon
    """
    return s.update_topology(str(isd_id), str(ad_id), topology)


@run_remote
def send_update(s, isd_id, ad_id, arch_path):
    """
    send_update XML-RPC call to the management daemon
    """

    with open(arch_path, 'rb') as update_fh:
        raw_data = update_fh.read()

    data_digest = hashlib.sha1(raw_data).hexdigest()
    base64_data = str(base64.b64encode(raw_data), 'utf-8')

    data_dict = {'data': base64_data, 'digest': data_digest,
                 'name': os.path.basename(arch_path)}
    update_response = s.send_update(str(isd_id), str(ad_id), data_dict)
    return update_response


@run_remote
def control_process(s, isd_id, ad_id, process_id, command):
    return s.control_process(str(isd_id), str(ad_id), process_id, command)


@run_remote
def get_master_id(s, isd_id, ad_id, server_type):
    return s.get_master_id(str(isd_id), str(ad_id), server_type)


@run_remote
def read_log(s, process_name):
    to_read = 4000
    return s.tail_process_log(process_name, 0, to_read)
