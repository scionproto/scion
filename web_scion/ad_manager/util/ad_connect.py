from copy import deepcopy
from ipaddress import ip_address
import json
import tempfile
from lib.util import read_file, write_file
from topology.generator import ConfigGenerator, PORT, ER_RANGE

temp_out_dir = '/home/tonyo/scion_ethz/scion/topology/tmp'
path_policy_file = '/home/tonyo/scion_ethz/scion/topology/PathPolicy.json'


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
        ip_address_loc = ip_address('.'.join([first_byte, isd_id,
                                              ad_id, ER_RANGE]))
        ip_address_pub = generator.increment_address(ip_address_loc, mask)
        new_router = {
                    'AddrType': 'IPv4',
                    'Addr': str(ip_address_loc),
                    'Interface': {
                        'AddrType': 'IPv4',
                        'Addr': str(ip_address_pub),
                        'UdpPort': int(PORT),
                        'ToUdpPort': int(PORT)}
        }
        last_index = 0
    return str(last_index + 1), new_router


def update_topos(generator, new_topo, existing_topo):
    new_topo = deepcopy(new_topo)
    existing_topo = deepcopy(existing_topo)
    new_id, new_topo_router = create_next_router(generator, new_topo)
    ex_id, existing_topo_router = create_next_router(generator, existing_topo)

    new_router_if = new_topo_router['Interface']
    existing_router_if = existing_topo_router['Interface']

    new_ad_id = new_topo['ADID']
    existing_ad_id = existing_topo['ADID']

    if_id = generator.generate_if_id(new_ad_id, existing_ad_id)

    new_router_if['ToAddr'] = existing_router_if['Addr']
    new_router_if['NeighborISD'] = existing_topo['ISDID']
    new_router_if['NeighborAD'] = existing_ad_id
    new_router_if['NeighborType'] = 'PARENT'
    new_router_if['IFID'] = if_id

    existing_router_if['ToAddr'] = new_router_if['Addr']
    existing_router_if['NeighborISD'] = new_topo['ISDID']
    existing_router_if['NeighborAD'] = new_ad_id
    existing_router_if['NeighborType'] = 'CHILD'
    existing_router_if['IFID'] = if_id

    new_topo['EdgeRouters'][new_id] = new_topo_router
    existing_topo['EdgeRouters'][ex_id] = existing_topo_router

    return new_topo, existing_topo


def create_new_ad(parent_ad_topo, isd_id, ad_id, out_dir=None):
    isd_ad_id = '{}-{}'.format(isd_id, ad_id)
    ad_dict = {isd_ad_id: {'level': 'LEAF'}}
    gen = ConfigGenerator(out_dir=out_dir)

    with tempfile.NamedTemporaryFile('w') as temp_fh:
        json.dump(ad_dict, temp_fh)
        temp_fh.flush()
        gen.generate_all(temp_fh.name, path_policy_file)

    new_topo_path = gen.path_dict(isd_id, ad_id)['topo_file_abs']
    new_topo_file = read_file(new_topo_path)
    new_topo = json.loads(new_topo_file)
    new_topo, existing_topo = update_topos(gen, new_topo, parent_ad_topo)
    write_file(new_topo_path, json.dumps(new_topo))
    gen.write_derivatives(new_topo)
    return new_topo, existing_topo


if __name__ == '__main__':
    # generate_config()

    config_generator = ConfigGenerator(temp_out_dir)

    old_file = '/home/tonyo/scion_ethz/scion/topology/ISD1/topologies/ISD:1-AD:11.json'
    old_topo = json.loads(open(old_file).read())

    #new_file = '/home/tonyo/scion_ethz/scion/topology/tmp/ISD12/topologies/ISD:12-AD:34.json'
    #new_topo = json.loads(open(new_file).read())


    create_new_ad(old_topo, 34, 56)
    a = 1
