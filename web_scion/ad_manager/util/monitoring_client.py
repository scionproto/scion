import xmlrpc.client


ISD_AD_ID_DIVISOR = '-'

def get_supervisor_server():
    return xmlrpc.client.ServerProxy('https://localhost:9000')


def get_ad_info(isd_id, ad_id):
    s = get_supervisor_server()
    isd_ad_id = ISD_AD_ID_DIVISOR.join([isd_id, ad_id])
    try:
        ad_info = s.get_ad_info(isd_ad_id)
        return ad_info
    except (ConnectionRefusedError, xmlrpc.client.Error):
        return None
