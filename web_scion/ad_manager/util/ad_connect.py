# Stdlib
import json
import os
import tempfile
from copy import deepcopy
from ipaddress import ip_address

# SCION
from lib.defines import TOPOLOGY_PATH
from lib.topology import Topology
from lib.util import read_file, write_file
from topology.generator import ConfigGenerator, PORT


def find_last_router(topo_dict):
    assert 'EdgeRouters' in topo_dict
    routers = topo_dict['EdgeRouters']
    if routers:
        sorted_routers = sorted(routers.items(),
                                key=lambda pair: ip_address(pair[1]['Addr']))
        return sorted_routers[-1]
    else:
        return None


def create_next_router(generator, topo_dict):
    router_item = find_last_router(topo_dict)
    first_byte, mask = generator.get_subnet_params()
    if router_item:
        _, last_router = router_item
        new_router = deepcopy(last_router)
        lr_addr = last_router['Addr']
        lr_interface_addr = last_router['Interface']['Addr']

        nr_addr = generator.increment_address(lr_addr, mask, 2)
        nr_if_addr = generator.increment_address(lr_interface_addr, mask, 2)

        new_router['Addr'] = nr_addr
        new_router['Interface']['Addr'] = nr_if_addr
        new_router['Interface']['ToAddr'] = 'NULL'

        last_index = int(sorted(topo_dict['EdgeRouters'].keys(),
                                key=lambda x: int(x))[-1])

    else:
        isd_id = str(topo_dict['ISDID'])
        ad_id = str(topo_dict['ADID'])
        # FIXME(rev112): Legacy approach, fixed in later commits
        er_range = '81'
        ip_address_loc = ip_address('.'.join([first_byte, isd_id,
                                              ad_id, er_range]))
        ip_address_pub = generator.increment_address(ip_address_loc, mask)
        new_router = {
            'AddrType': 'IPv4',
            'Addr': str(ip_address_loc),
            'Interface': {
                'AddrType': 'IPv4',
                'Addr': str(ip_address_pub),
                'UdpPort': int(PORT),
                'ToUdpPort': int(PORT),
            },
        }
        last_index = 0
    return str(last_index + 1), new_router


def link_topologies(generator, first_topo, second_topo, link_type):
    """

    link_type:
    ROUTING -- both are ROUTING
    PEER -- both are PEER
    PARENT_CHILD -- first_topo is now a parent of second_topo
    """
    first_topo = deepcopy(first_topo)
    second_topo = deepcopy(second_topo)
    first_router_id, first_topo_router = create_next_router(generator,
                                                            first_topo)
    second_router_id, second_topo_router = create_next_router(generator,
                                                              second_topo)

    first_router_if = first_topo_router['Interface']
    second_router_if = second_topo_router['Interface']

    first_ad_id = first_topo['ADID']
    second_ad_id = second_topo['ADID']

    # FIXME(rev112)
    if_id = first_ad_id + second_ad_id

    first_router_if['ToAddr'] = second_router_if['Addr']
    first_router_if['NeighborISD'] = second_topo['ISDID']
    first_router_if['NeighborAD'] = second_ad_id
    first_router_if['IFID'] = if_id

    second_router_if['ToAddr'] = first_router_if['Addr']
    second_router_if['NeighborISD'] = first_topo['ISDID']
    second_router_if['NeighborAD'] = first_ad_id
    second_router_if['IFID'] = if_id

    if link_type == 'ROUTING':
        first_router_if['NeighborType'] = 'ROUTING'
        second_router_if['NeighborType'] = 'ROUTING'
    elif link_type == 'PEER':
        first_router_if['NeighborType'] = 'PEER'
        second_router_if['NeighborType'] = 'PEER'
    elif link_type == 'PARENT_CHILD':
        first_router_if['NeighborType'] = 'CHILD'
        second_router_if['NeighborType'] = 'PARENT'
    else:
        raise Exception('Invalid link type')

    first_topo['EdgeRouters'][first_router_id] = first_topo_router
    second_topo['EdgeRouters'][second_router_id] = second_topo_router

    return first_topo, second_topo


def link_ads(first_ad, second_ad, link_type):
    """Needs transaction!"""
    first_topo = first_ad.generate_topology_dict()
    second_topo = second_ad.generate_topology_dict()
    gen = ConfigGenerator()
    first_topo, second_topo = link_topologies(gen, first_topo, second_topo,
                                              link_type)

    new_first_topo = Topology.from_dict(first_topo)
    new_second_topo = Topology.from_dict(second_topo)

    first_ad.fill_from_topology(new_first_topo, clear=True)
    second_ad.fill_from_topology(new_second_topo, clear=True)


def create_new_ad(parent_ad_topo, isd_id, ad_id, out_dir=None):
    isd_ad_id = '{}-{}'.format(isd_id, ad_id)
    ad_dict = {isd_ad_id: {'level': 'LEAF'}}
    gen = ConfigGenerator(out_dir=out_dir)

    path_policy_file = os.path.join(TOPOLOGY_PATH, 'PathPolicy.json')
    with tempfile.NamedTemporaryFile('w') as temp_fh:
        json.dump(ad_dict, temp_fh)
        temp_fh.flush()
        gen.generate_all(temp_fh.name, path_policy_file)

    new_topo_path = gen.path_dict(isd_id, ad_id)['topo_file_abs']
    new_topo_file = read_file(new_topo_path)
    new_topo = json.loads(new_topo_file)
    existing_topo, new_topo = link_topologies(gen, parent_ad_topo, new_topo,
                                              'PARENT_CHILD')
    write_file(new_topo_path, json.dumps(new_topo))
    gen.write_derivatives(new_topo)
    return new_topo, existing_topo
