#!/usr/bin/env python3
import base64
import os
import sys
import hashlib
from subprocess import Popen
from daemon_monitor.common import (get_supervisor_server, UPDATE_DIR,
    MONITORING_DAEMON_PORT, UPDATE_SCRIPT_PATH, response_success, is_success,
    response_failure)

from daemon_monitor.secure_rpc_server import XMLRPCServerTLS
from topology.generator import TOPO_DIR, SCRIPTS_DIR


class MonitoringServer(object):

    def __init__(self, addr):
        super().__init__()
        self.addr = addr

        self.rpc_server = XMLRPCServerTLS((self.addr, MONITORING_DAEMON_PORT))
        self.rpc_server.register_introspection_functions()

        # Register functions
        self.rpc_server.register_function(self.get_topology)
        self.rpc_server.register_function(self.get_process_info)
        self.rpc_server.register_function(self.control_process)
        self.rpc_server.register_function(self.get_ad_info)
        self.rpc_server.register_function(self.send_update)

        print("Server started...")
        self.rpc_server.serve_forever()

    def get_full_ad_name(self, isd_id, ad_id):
        return 'ad{}-{}'.format(isd_id, ad_id)

    # COMMAND
    def get_topology(self, isd_id, ad_id):
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id
        topo_file = os.path.join('ISD' + isd_id, TOPO_DIR, file_name + '.json')
        topo_path = os.path.join('..', SCRIPTS_DIR, topo_file)
        return response_success(open(topo_path, 'r').read())

    # COMMAND
    def get_ad_info(self, isd_id, ad_id):
        ad_name = self.get_full_ad_name(isd_id, ad_id)
        server = get_supervisor_server()
        all_process_info = server.supervisor.getAllProcessInfo()
        ad_process_info = list(filter(lambda x: x['group'] == ad_name,
                                      all_process_info))
        return response_success(list(ad_process_info))

    # COMMAND
    def get_process_info(self, full_process_name):
        server = get_supervisor_server()
        info = server.supervisor.getProcessInfo(full_process_name)
        return response_success(info)

    def get_process_state(self, full_process_name):
        info_response = self.get_process_info(full_process_name)
        if is_success(info_response):
            info = info_response[1]
            return info['statename']
        else:
            return '???'

    def start_process(self, process_name):
        if self.get_process_state(process_name) in ['RUNNING', 'STARTING']:
            return True
        server = get_supervisor_server()
        return server.supervisor.startProcess(process_name)

    def stop_process(self, process_name):
        if self.get_process_state(process_name) not in ['RUNNING', 'STARTING']:
            return True
        server = get_supervisor_server()
        return server.supervisor.stopProcess(process_name)

    # COMMAND
    def control_process(self, isd_id, ad_id, process_name, command):
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
            return response_failure('Invalid command')
        return response_success(res)

    def do_update(self, archive, path):
        Popen([sys.executable, UPDATE_SCRIPT_PATH, archive, path])

    # COMMAND
    def send_update(self, isd_id, ad_id, data_dict):
        # Verify the hash value
        base64_data = data_dict['data']
        received_digest = data_dict['digest']
        raw_data = base64.b64decode(base64_data)
        if hashlib.sha1(raw_data).hexdigest() != received_digest:
            return response_failure('Hash value does not match')

        if not os.path.exists(UPDATE_DIR):
            os.makedirs(UPDATE_DIR)
        archive_name = os.path.basename(data_dict['name'])
        out_file_path = os.path.join(UPDATE_DIR, archive_name)
        with open(out_file_path, 'wb') as out_file_fh:
            out_file_fh.write(raw_data)
        # self.do_update(out_file, SCION_ROOT)
        self.do_update(out_file_path, UPDATE_DIR)
        return response_success()

if __name__ == "__main__":
    MonitoringServer(sys.argv[1])
