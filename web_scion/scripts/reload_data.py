#!/usr/bin/env python3

"""
Import ISD/AD data from topology files
"""

# Stdlib
import glob
import os
import sys
from os.path import dirname as dir
sys.path.insert(0, dir(dir(dir(os.path.abspath(__file__)))))

# External packages
import django

# SCION
from ad_management.common import WEB_SCION_DIR
from lib.defines import TOPOLOGY_PATH
from lib.topology import Topology

# Set up the Django environment
os.environ['DJANGO_SETTINGS_MODULE'] = 'web_scion.settings'
sys.path.insert(0, WEB_SCION_DIR)
django.setup()

# Django app imports
from ad_manager.models import AD, ISD
from django.contrib.auth.models import User


def clear_everything():
    print('> Deleting everything...')
    ISD.objects.all().delete()


def add_users():
    """
    Create a superuser ('admin') and an ordinary user ('user1')
    """
    try:
        User.objects.get(username='admin').delete()
    except User.DoesNotExist:
        pass
    User.objects.create_superuser(username='admin', password='admin', email='')
    print('> Superuser was created')

    try:
        User.objects.get(username='user1').delete()
    except User.DoesNotExist:
        pass
    User.objects.create_user(username='user1', password='user1', email='')
    print('> User (user1) was created')


def reload_data():
    clear_everything()
    add_users()

    # Add model instances
    topology_files = glob.glob(os.path.join(TOPOLOGY_PATH,
                                            'ISD*', 'topologies', 'ISD*.json'))
    isds = {}
    ads = []

    for topo_file in topology_files:
        topology = Topology.from_file(topo_file)
        isds[topology.isd_id] = topology.isd_id
        ads.append(topology)
    ads = sorted(ads, key=lambda topo: topo.ad_id)

    # Add ISDs
    for isd_id in isds:
        isd = ISD(id=isd_id)
        isd.save()
        isds[isd_id] = isd
    print("> {} ISD(s) were loaded".format(len(isds)))

    # First, save all add ADs to avoid IntegrityError
    for ad_topo in ads:
        ad = AD(id=ad_topo.ad_id, isd=isds[ad_topo.isd_id],
                is_core_ad=ad_topo.is_core_ad, dns_domain=ad_topo.dns_domain)
        ad.save()

    # Add routers, servers, etc.
    for ad_topo in ads:
        ad = AD.objects.get(id=ad_topo.ad_id, isd=isds[ad_topo.isd_id])
        ad.fill_from_topology(ad_topo)
        print('> AD {} is loaded'.format(ad))

if __name__ == "__main__":
    reload_data()
