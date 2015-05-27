#!/usr/bin/env python3

# Import ISD/AD data from topology files

import glob
import os
import sys

from ad_management.common import WEB_SCION_DIR
from lib.defines import TOPOLOGY_PATH

os.environ['DJANGO_SETTINGS_MODULE'] = 'web_scion.settings'
sys.path.insert(0, WEB_SCION_DIR)

import django
from django.contrib.auth.models import User
from ad_manager.models import AD, ISD
from lib.topology import Topology

django.setup()

# Create a superuser
try:
    User.objects.get(username='admin')
except User.DoesNotExist:
    User.objects.create_superuser(username='admin', password='admin', email='')
    print('> Superuser created')

# Add model instances
topology_files = glob.glob(os.path.join(TOPOLOGY_PATH,
                                        'ISD*/topologies/ISD*.json'))
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
print("> {} ISDs added".format(len(isds)))


# First, save all add ADs to avoid IntegrityError
for ad_topo in ads:
    ad = AD(id=ad_topo.ad_id, isd=isds[ad_topo.isd_id],
            is_core_ad=ad_topo.is_core_ad)
    ad.save()

# Add routers, servers, etc.
for ad_topo in ads:
    ad = AD.objects.get(id=ad_topo.ad_id, isd=isds[ad_topo.isd_id])
    ad.fill_from_topology(ad_topo)
    print('> AD {} added'.format(ad))
