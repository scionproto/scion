#!/usr/bin/env python3

"""
Import ISD/AD data from topology files
"""

# Stdlib
import glob
import os
import sys
from os.path import dirname as d

sys.path.insert(0, d(d(d(os.path.abspath(__file__)))))

# External packages
import django
from django.db import transaction

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
    transaction.set_autocommit(False)
    clear_everything()
    add_users()

    # Add model instances
    topology_files = glob.glob(os.path.join(TOPOLOGY_PATH,
                                            'ISD*', 'topologies', 'ISD:*.json'))
    ad_num = len(topology_files)
    print("> {} topology files found".format(ad_num))
    isds = {}
    ad_topos = []
    ad_ids = set()

    same_ad_ids = False
    for topo_file in topology_files:
        topology = Topology.from_file(topo_file)
        isds[topology.isd_id] = None
        if not same_ad_ids and topology.ad_id in ad_ids:
            same_ad_ids = True
        ad_ids.add(topology.ad_id)
        ad_topos.append(topology)

    ad_topos = sorted(ad_topos, key=lambda t: t.ad_id)
    assert len(ad_topos) == ad_num

    id_map = {}
    if same_ad_ids:
        print("> Several ADs with identical IDs are found. Currently, this "
              "case is not supported. Renumerating ADs...")
        ad_id = 1
        for topo in ad_topos:
            id_map[(topo.ad_id, topo.isd_id)] = ad_id
            topo.ad_id = ad_id
            ad_id += 1

        # Fixing routers
        for topo in ad_topos:
            routers = topo.get_all_edge_routers()
            for router in routers:
                neighbor_id = router.interface.neighbor_ad
                new_neighbor_id = id_map[(neighbor_id,
                                          router.interface.neighbor_isd)]
                router.interface.neighbor_ad = new_neighbor_id

    # Add ISDs
    for isd_id in sorted(isds.keys()):
        isd = ISD(id=isd_id)
        isd.save()
        isds[isd_id] = isd
    print(isds)

    # First, save all add ADs to avoid IntegrityError
    report_ranges = {int(ad_num / 10.0 * x): x * 10 for x in range(1, 11)}
    print(report_ranges)
    for i, ad_topo in enumerate(ad_topos, start=1):
        if i in report_ranges:
            print("{}%".format(report_ranges[i]))
        # print("Saving AD {}-{}".format(ad_topo.isd_id, ad_topo.ad_id))
        ad = AD(id=ad_topo.ad_id, isd=isds[ad_topo.isd_id],
                is_core_ad=ad_topo.is_core_ad, dns_domain=ad_topo.dns_domain)
        ad.save()
    transaction.commit()

    print("> ADs instances were added")
    # Add routers, servers, etc.
    for ad_topo in ad_topos:
        ad = AD.objects.get(id=ad_topo.ad_id, isd=isds[ad_topo.isd_id])
        ad.fill_from_topology(ad_topo)
        print('> AD {} is loaded'.format(ad))
    transaction.commit()
    transaction.set_autocommit(True)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'users':
        add_users()
    else:
        reload_data()
