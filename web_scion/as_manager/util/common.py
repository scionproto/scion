# StdLib
from ipaddress import ip_address


def is_private_address(ip_addr):
    ip_addr = ip_address(ip_addr)
    return str(ip_addr).startswith('127.')


def empty_dict():
    """
    Needed for default value of JSONField.

    :return: empty dictionary
    :rtype: dict
    """
    return {}
