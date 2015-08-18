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
:mod:`management_daemon` --- AD management daemon
======================================================
"""
# Stdlib
import base64
import hashlib
import json
import logging
import os
import sys
import time
import xmlrpc.client
from multiprocessing import Process
from subprocess import Popen

# External packages
from kazoo.client import KazooClient
from kazoo.exceptions import NoNodeError

# SCION
from ad_management.common import (
    LOGS_DIR,
    MANAGEMENT_DAEMON_PORT,
    MANAGEMENT_DAEMON_PROC_NAME,
    UPDATE_DIR_PATH,
    UPDATE_SCRIPT_PATH,
)
from ad_management.secure_rpc import XMLRPCServerTLS
from ad_management.util import (
    get_supervisor_server,
    response_failure,
    response_success,
)
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    PROJECT_ROOT,
)
from lib.log import init_logging
from topology.generator import ConfigGenerator

MD_START_RETRIES = 3
MD_SLEEP_BEFORE_TRY = 1


def start_md():
    # Start the management daemon
    server = get_supervisor_server()
    started = False

    logging.info('Trying to start the management daemon')
    for _ in range(MD_START_RETRIES):
        time.sleep(MD_SLEEP_BEFORE_TRY)
        try:
            server.supervisor.startProcess(MANAGEMENT_DAEMON_PROC_NAME,
                                           wait=True)

            process_info = server.supervisor.getProcessInfo(
                MANAGEMENT_DAEMON_PROC_NAME
            )
            if process_info['statename'] == 'RUNNING':
                started = True
                break
        except (ConnectionRefusedError, xmlrpc.client.Fault) as ex:
            logging.warning('Error:' + str(ex))

    if started:
        logging.info('The management daemon is running')
    else:
        logging.warning('Could not start the management daemon')
    return started


class ManagementDaemon(object):
    """
    Daemon which is launched on every AD node.

    It serves as a RPC server for the web panel and as a client to
    Supervisor and Zookeeper, proxying corresponding commands to them.
    It also runs updater and generates software packages.

    :ivar addr:
    :type addr:
    :ivar rpc_server:
    :type rpc_server:
    """

    def __init__(self, addr):
        """
        Initialize an instance of the class ManagementDaemon.

        :param addr:
        :type addr:
        """
        super().__init__()
        self.addr = addr
        self.rpc_server = XMLRPCServerTLS((self.addr, MANAGEMENT_DAEMON_PORT))
        self.rpc_server.register_introspection_functions()
        # Register functions
        to_register = [self.get_topology,
                       self.control_process, self.get_ad_info,
                       self.update_topology,
                       self.get_master_id, self.tail_process_log]
        for func in to_register:
            self.rpc_server.register_function(func)
        logging.info("Management daemon started")
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

    def get_topo_path(self, isd_id, ad_id):
        gen = ConfigGenerator()
        topo_path = gen.path_dict(isd_id, ad_id)['topo_file_abs']
        return topo_path

    def stop_process_group_async(self, isd_id, ad_id):
        """
        Stop all the processes for the specified AD after some delay, so the
        initial RPC call has time to finish.
        """
        wait_before_restart = 0.1

        def _stop_process_group_wait():
            time.sleep(wait_before_restart)
            server = get_supervisor_server()
            server.supervisor.stopProcessGroup("ad{}-{}".format(isd_id, ad_id))
            start_md()

        p = Process(target=_stop_process_group_wait)
        p.start()

    def update_topology(self, isd_id, ad_id, topology):
        # TODO(rev112) check security!
        topo_path = self.get_topo_path(isd_id, ad_id)
        if not os.path.isfile(topo_path):
            return response_failure('No AD topology found')
        with open(topo_path, 'w') as topo_fh:
            json.dump(topology, topo_fh, sort_keys=True, indent=4)
            logging.info('Topology file written')
        generator = ConfigGenerator()
        generator.write_derivatives(topology)
        self.stop_process_group_async(isd_id, ad_id)
        return response_success('Topology file is successfully updated')

    def _read_topology(self, isd_id, ad_id):
        topo_path = self.get_topo_path(isd_id, ad_id)
        try:
            return open(topo_path, 'r').read()
        except OSError as e:
            logging.error("Error opening {}: {}".format(topo_path,
                                                        str(e)))
            return None

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
        topology = self._read_topology(isd_id, ad_id)
        if topology:
            return response_success(topology)
        else:
            return response_failure('Cannot read topology file')

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
        if ad_process_info:
            return response_success(list(ad_process_info))
        else:
            return response_failure('AD not found')

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
        return info

    def get_process_state(self, full_process_name):
        """
        Return process state (RUNNING, STARTING, etc.).

        :param full_process_name:
        :type full_process_name:
        :returns:
        :rtype:
        """
        info_response = self.get_process_info(full_process_name)
        if info_response:
            return info_response['statename']
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

    def tail_process_log(self, process_name, offset, length):
        """
        Read the last part of a log file.

        :param process_name:
        :type process_name: str
        :param offset:
        :type offset: int
        :param length:
        :type length: int
        :return:
        """
        server = get_supervisor_server()
        data = server.supervisor.tailProcessStdoutLog(process_name,
                                                      offset, length)
        return response_success(data)

    def run_updater(self, archive, path):
        """
        Launch the updater in a new process.

        :param archive:
        :type archive:
        :param path:
        :type path:
        """
        updater_log = open(os.path.join(LOGS_DIR, 'updater.log'), 'a')
        Popen([sys.executable, UPDATE_SCRIPT_PATH, archive, path],
              stdout=updater_log, stderr=updater_log)

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
        :returns: confirmation or error
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
        self.run_updater(out_file_path, PROJECT_ROOT)
        return response_success()

    def get_master_id(self, isd_id, ad_id, server_type):

        """
        Get the id of the current master process for a given server type.
        Registered function.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param server_type: one of 'bs', 'cs', 'ps' or 'ds'
        :type server_type: str
        :returns: master server id or error
        :rtype:
        """
        if server_type not in [BEACON_SERVICE, CERTIFICATE_SERVICE,
                               PATH_SERVICE, DNS_SERVICE]:
            return response_failure('Invalid server type')

        topology_str = self._read_topology(isd_id, ad_id)
        try:
            topology = json.loads(topology_str)
        except (ValueError, KeyError, TypeError):
            return response_failure('Cannot parse topology file')

        # Read zookeeper config
        zookeeper_dict = topology["Zookeepers"]
        zookeper_hosts = ["{}:{}".format(zk_host["Addr"], zk_host["ClientPort"])
                          for zk_host in zookeeper_dict.values()]

        kc = KazooClient(hosts=','.join(zookeper_hosts))
        lock_path = '/ISD{}-AD{}/{}/lock'.format(isd_id, ad_id, server_type)
        get_id = lambda name: name.split('__')[-1]
        try:
            kc.start()
            contenders = kc.get_children(lock_path)
            if not contenders:
                return response_failure('No lock contenders found')

            lock_holder_file = sorted(contenders, key=get_id)[0]
            lock_holder_path = os.path.join(lock_path, lock_holder_file)
            lock_contents = kc.get(lock_holder_path)
            server_id, _, _ = lock_contents[0].split(b"\x00")
            server_id = str(server_id, 'utf-8')
            return response_success(server_id)
        except NoNodeError:
            return response_failure('No lock data found')
        finally:
            kc.stop()


if __name__ == "__main__":
    init_logging(sys.argv[2])
    ManagementDaemon(sys.argv[1])
