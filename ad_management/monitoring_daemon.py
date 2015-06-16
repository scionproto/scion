#!/usr/bin/env python3
# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`monitoring_daemon` --- Ad management tool daemon
======================================================
"""
# Stdlib
import base64
import hashlib
import logging
import os
import sys
from subprocess import Popen

# SCION
from ad_management.common import (
    get_supervisor_server,
    is_success,
    MONITORING_DAEMON_PORT,
    response_failure,
    response_success,
    SCION_ROOT,
    UPDATE_DIR_PATH,
    UPDATE_SCRIPT_PATH,
)
from ad_management.secure_rpc_server import XMLRPCServerTLS
from lib.log import init_logging
from topology.generator import TOPO_DIR, SCRIPTS_DIR


class MonitoringDaemon(object):
    """


    :ivar addr:
    :type addr:
    :ivar rpc_server:
    :type rpc_server:
    """

    def __init__(self, addr):
        """
        Initialize an instance of the class MonitoringDaemon.

        :param addr:
        :type addr:
        """
        super().__init__()
        self.addr = addr
        self.rpc_server = XMLRPCServerTLS((self.addr, MONITORING_DAEMON_PORT))
        self.rpc_server.register_introspection_functions()
        # Register functions
        to_register = [self.get_topology, self.get_process_info,
                       self.control_process, self.get_ad_info]
        for func in to_register:
            self.rpc_server.register_function(func)
        logging.info("Monitoring daemon started")
        self.rpc_server.serve_forever()

    def get_full_ad_name(self, isd_id, ad_id):
        """
        Return the full AD name.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :returns: the full AD name.
        :rtype: string
        """
        return 'ad{}-{}'.format(isd_id, ad_id)

    def get_topology(self, isd_id, ad_id):
        """
        Read topology file of the given AD.
        Registered function.
        
        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :returns:
        :rtype:
        """
        isd_id, ad_id = str(isd_id), str(ad_id)
        logging.info('get_topology call')
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '.json'
        topo_file = os.path.join('ISD' + isd_id, TOPO_DIR, file_name)
        topo_path = os.path.join('..', SCRIPTS_DIR, topo_file)
        if os.path.isfile(topo_path):
            return response_success(open(topo_path, 'r').read())
        else:
            return response_failure('No topology file found')

    def get_ad_info(self, isd_id, ad_id):
        """
        Get status of all processes for the given AD.
        Registered function.
        
        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :returns:
        :rtype:
        """
        logging.info('get_ad_info call')
        ad_name = self.get_full_ad_name(isd_id, ad_id)
        server = get_supervisor_server()
        all_process_info = server.supervisor.getAllProcessInfo()
        ad_process_info = list(filter(lambda x: x['group'] == ad_name,
                                      all_process_info))
        return response_success(list(ad_process_info))

    def get_process_info(self, full_process_name):
        """
        Get process information (status, running time, etc.).
        Registered function.
        
        :param full_process_name:
        :type full_process_name:
        :returns:
        :rtype:
        """
        logging.info('get_process_info call')
        server = get_supervisor_server()
        info = server.supervisor.getProcessInfo(full_process_name)
        return response_success(info)

    def get_process_state(self, full_process_name):
        """
        Return process state (RUNNING, STARTING, etc.).

        :param full_process_name:
        :type full_process_name:
        :returns:
        :rtype:
        """
        info_response = self.get_process_info(full_process_name)
        if is_success(info_response):
            info = info_response[1]
            return info['statename']
        else:
            return None

    def start_process(self, process_name):
        """
        Start a process.

        :param process_name:
        :type process_name:
        :returns:
        :rtype:
        """
        if self.get_process_state(process_name) in ['RUNNING', 'STARTING']:
            return True
        server = get_supervisor_server()
        return server.supervisor.startProcess(process_name)

    def stop_process(self, process_name):
        """
        Stop a process.

        :param process_name:
        :type process_name:
        :returns:
        :rtype:
        """
        if self.get_process_state(process_name) not in ['RUNNING', 'STARTING']:
            return True
        server = get_supervisor_server()
        return server.supervisor.stopProcess(process_name)

    def control_process(self, isd_id, ad_id, process_name, command):
        """
        Send the command to the given process of the specified AD.
        Registered function.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param process_name:
        :type process_name:
        :param command:
        :type command:
        :returns:
        :rtype:
        """
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

    def run_updater(self, archive, path):
        """
        Launch the updater in a new process.

        :param archive:
        :type archive:
        :param path:
        :type path:
        """
        Popen([sys.executable, UPDATE_SCRIPT_PATH, archive, path])

    def send_update(self, isd_id, ad_id, data_dict):
        """
        Verify and extract the received update archive.
        Registered function.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param data_dict:
        :type data_dict:
        :returns:
        :rtype:
        """
        # Verify the hash value
        base64_data = data_dict['data']
        received_digest = data_dict['digest']
        raw_data = base64.b64decode(base64_data)
        if hashlib.sha1(raw_data).hexdigest() != received_digest:
            return response_failure('Hash value does not match')

        if not os.path.exists(UPDATE_DIR_PATH):
            os.makedirs(UPDATE_DIR_PATH)
        assert os.path.isdir(UPDATE_DIR_PATH)
        archive_name = os.path.basename(data_dict['name'])
        out_file_path = os.path.join(UPDATE_DIR_PATH, archive_name)
        with open(out_file_path, 'wb') as out_file_fh:
            out_file_fh.write(raw_data)
        self.run_updater(out_file_path, SCION_ROOT)
        return response_success()

if __name__ == "__main__":
    init_logging()
    MonitoringDaemon(sys.argv[1])
