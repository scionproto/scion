#!/usr/bin/env python3
import sys
import xmlrpc.client
from daemon_monitor.secure_rpc_server import XMLRPCServerTLS
from lib.config import Config
from lib.topology import Topology
from topology.generator import ISD_AD_ID_DIVISOR, TOPO_DIR, SCRIPTS_DIR


class MonitoringServer(object):

    def __init__(self, addr, topo_file, config_file):
        super().__init__()
        self.addr = addr
        self.topo_file = topo_file
        self.config_file = config_file
        self.topology = Topology(self.topo_file)
        self.config = Config(self.config_file)

        self.rpc_server = XMLRPCServerTLS((self.addr, 8000))
        self.rpc_server.register_introspection_functions()

        # Register functions
        self.rpc_server.register_function(self.get_topology)
        self.rpc_server.register_function(self.get_process_info)
        self.rpc_server.register_function(self.control_process)

        print("Server started...")
        self.rpc_server.serve_forever()

    def get_supervisor_server(self):
        return xmlrpc.client.ServerProxy('http://localhost:9001/RPC2')

    # COMMAND
    def get_topology(self, isd_ad_id):
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        assert self.topology.ad_id == int(ad_id) \
               and self.topology.isd_id == int(isd_id)
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id
        topo_file = 'ISD' + isd_id + TOPO_DIR + file_name + '-V:0.json'
        topo_path = ''.join(['..', SCRIPTS_DIR, topo_file])
        return open(topo_path, 'r').read()

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

    def control_process(self, isd_ad_id, process_name, command):
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        assert self.topology.ad_id == int(ad_id) \
               and self.topology.isd_id == int(isd_id)
        ad_name = 'ad{}-{}'.format(isd_id, ad_id)
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


if __name__ == "__main__":
    MonitoringServer(sys.argv[1], sys.argv[2], sys.argv[3])
