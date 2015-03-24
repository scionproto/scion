#!/usr/bin/env python3
import base64
import sys
import xmlrpc.client
from daemon_monitor.secure_rpc_server import XMLRPCServerTLS
from lib.crypto.symcrypto import sha3hash
from topology.generator import ISD_AD_ID_DIVISOR, TOPO_DIR, SCRIPTS_DIR

LISTEN_PORT = 9000


class MonitoringServer(object):

    def __init__(self, addr):
        super().__init__()
        self.addr = addr

        self.rpc_server = XMLRPCServerTLS((self.addr, LISTEN_PORT))
        self.rpc_server.register_introspection_functions()

        # Register functions
        self.rpc_server.register_function(self.get_topology)
        self.rpc_server.register_function(self.get_process_info)
        self.rpc_server.register_function(self.control_process)
        self.rpc_server.register_function(self.get_ad_info)
        self.rpc_server.register_function(self.send_update)

        print("Server started...")
        self.rpc_server.serve_forever()

    def get_supervisor_server(self):
        return xmlrpc.client.ServerProxy('http://localhost:9001/RPC2')

    def get_full_ad_name(self, isd_id, ad_id):
        return 'ad{}-{}'.format(isd_id, ad_id)

    # COMMAND
    def get_topology(self, isd_ad_id):
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id
        topo_file = 'ISD' + isd_id + TOPO_DIR + file_name + '-V:0.json'
        topo_path = ''.join(['..', SCRIPTS_DIR, topo_file])
        return open(topo_path, 'r').read()

    def get_ad_info(self, isd_ad_id):
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        ad_name = self.get_full_ad_name(isd_id, ad_id)
        server = self.get_supervisor_server()
        all_process_info = server.supervisor.getAllProcessInfo()
        ad_process_info = list(filter(lambda x: x['group'] == ad_name,
                                      all_process_info))
        return list(ad_process_info)

    # COMMAND
    def get_process_info(self, full_process_name):
        server = self.get_supervisor_server()
        info = server.supervisor.getProcessInfo(full_process_name)
        return info

    def get_process_state(self, full_process_name):
        info = self.get_process_info(full_process_name)
        return info['statename']

    def start_process(self, process_name):
        if self.get_process_state(process_name) in ['RUNNING', 'STARTING']:
            return True
        server = self.get_supervisor_server()
        return server.supervisor.startProcess(process_name)

    def stop_process(self, process_name):
        if self.get_process_state(process_name) not in ['RUNNING', 'STARTING']:
            return True
        server = self.get_supervisor_server()
        return server.supervisor.stopProcess(process_name)

    # COMMAND
    def control_process(self, isd_ad_id, process_name, command):
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        ad_name = self.get_full_ad_name(isd_id, ad_id)
        full_process_name = '{}:{}'.format(ad_name, process_name)
        if command == 'START':
            res = self.start_process(full_process_name)
        elif command == 'STOP':
            res = self.stop_process(full_process_name)
        elif command == 'RESTART':
            self.stop_process(full_process_name)
            res = self.start_process(full_process_name)
        else:
            raise Exception('Invalid command')
        return res

    # COMMAND
    def send_update(self, isd_ad_id, data_dict):
        base64_data = data_dict['data']
        received_digest = data_dict['digest']
        raw_data = base64.b64decode(base64_data)
        if sha3hash(raw_data) != received_digest:
            return None
        with open('out_file.tar.gz', 'wb') as out_file:
            out_file.write(raw_data)
        return True


if __name__ == "__main__":
    MonitoringServer(sys.argv[1])
