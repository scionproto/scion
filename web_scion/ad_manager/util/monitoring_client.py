import base64
import xmlrpc.client
from lib.crypto.symcrypto import sha3hash

ISD_AD_ID_DIVISOR = '-'


def get_supervisor_server():
    return xmlrpc.client.ServerProxy('https://localhost:9000')


def get_ad_info(isd_id, ad_id):
    s = get_supervisor_server()
    isd_ad_id = ISD_AD_ID_DIVISOR.join([isd_id, ad_id])
    try:
        ad_info = s.get_ad_info(isd_ad_id)
        return ad_info
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return None


def get_topology(isd_id, ad_id):
    s = get_supervisor_server()
    isd_ad_id = ISD_AD_ID_DIVISOR.join([isd_id, ad_id])
    try:
        topo = s.get_topology(isd_ad_id)
        return topo
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return None


def send_update(isd_id, ad_id, raw_data):
    s = get_supervisor_server()
    isd_ad_id = ISD_AD_ID_DIVISOR.join([isd_id, ad_id])

    data_digest = sha3hash(raw_data)
    base64_data = str(base64.b64encode(raw_data), 'utf-8')

    data_dict = {'data': base64_data, 'digest': data_digest}
    try:
        if not s.send_update(isd_ad_id, data_dict):
            return 'CANNOT UPDATE'
        return 'OK'
    except (ConnectionRefusedError, xmlrpc.client.Error) as ex:
        return None