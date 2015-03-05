import glob
import os
import sys
from django.db import IntegrityError

os.environ['DJANGO_SETTINGS_MODULE'] = 'web_scion.settings'
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

import django
from django.contrib.auth.models import User
from ad_manager.models import AD, ISD, RouterWeb, BeaconServerWeb, \
    CertificateServerWeb, PathServerWeb
from lib.topology import Topology

django.setup()

# Create superuser
try:
    User.objects.get(username='admin')
except User.DoesNotExist:
    User.objects.create_superuser(username='admin', password='admin', email='')
    print('> Superuser created')

# Add model instances
TOPOLOGY_DIR = '../../topology'
topology_files = glob.glob(TOPOLOGY_DIR + '/ISD*/topologies/*json')
isds = {}
ads = []

for topo_file in topology_files:
    topology = Topology(topo_file)
    isds[topology.isd_id] = topology.isd_id
    ads.append(topology)

# Add ISDs
for isd_id in isds:
    isd = ISD(id=isd_id)
    isd.save()
    isds[isd_id] = isd
print("> {} ISDs added".format(len(isds)))

# Add ADs
for ad_topo in ads:
    ad = AD(id=ad_topo.ad_id, isd=isds[ad_topo.isd_id])
    ad.save()
    # Routers
    routers = ad_topo.parent_edge_routers + ad_topo.child_edge_routers + \
              ad_topo.peer_edge_routers + ad_topo.routing_edge_routers
    beacon_servers = ad_topo.beacon_servers
    certificate_servers = ad_topo.certificate_servers
    path_servers = ad_topo.path_servers

    try:
        for router in routers:
            router_element = RouterWeb(addr=router.addr, ad=ad)
            router_element.save()

        for bs in beacon_servers:
            bs_element = BeaconServerWeb(addr=bs.addr, ad=ad)
            bs_element.save()

        for cs in certificate_servers:
            cs_element = CertificateServerWeb(addr=cs.addr, ad=ad)
            cs_element.save()

        for ps in path_servers:
            ps_element = PathServerWeb(addr=ps.addr, ad=ad)
            ps_element.save()
    except IntegrityError:
        pass

    print('> AD {} added'.format(ad))

