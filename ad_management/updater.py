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
:mod:`updater` --- Ad management updating tool
==============================================
"""
# Stdlib
import logging
import os
import subprocess
import sys
import tarfile
import time
import xmlrpc.client

# SCION
from ad_management.common import (
    get_supervisor_server,
    MONITORING_DAEMON_PROC_NAME,
    SCION_ROOT,
    SUPERVISORD_PATH,
)
from lib.log import init_logging


THIS_SCRIPT_PATH = os.path.abspath(__file__)
THIS_SCRIPT_DIR = os.path.dirname(THIS_SCRIPT_PATH)
THIS_SCRIPT_NAME = os.path.basename(THIS_SCRIPT_PATH)

IS_UPDATED_ARG = '--new'


def stop_everything():
    """
    Stop all processes managed by Supervisor.
    """
    logging.info('Stopping all processes...')
    server = get_supervisor_server()
    try:
        server.supervisor.stopAllProcesses()
    except (ConnectionRefusedError, xmlrpc.client.Fault) as ex:
        logging.warning('Could not stop processes')


def start_everything():
    """
    Start all processes managed by Supervisor.
    """
    logging.info('Starting all processes...')
    server = get_supervisor_server()
    try:
        server.supervisor.startAllProcesses()
    except (ConnectionRefusedError, xmlrpc.client.Fault) as ex:
        logging.warning('Could not start processes')


def start_monitoring_daemon():
    """
    Start the monitoring daemon process after the update.
    """
    # First, try to start Supervisor if not started
    exit_status = subprocess.call([SUPERVISORD_PATH, 'reload'],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
    logging.info('Supervisord exit status: {}'.format(exit_status))
    # Second, perform the API call
    logging.info('Starting the monitoring daemon...')
    server = get_supervisor_server()
    try:
        server.supervisor.startProcess(MONITORING_DAEMON_PROC_NAME)
    except (ConnectionRefusedError, xmlrpc.client.Fault) as ex:
        logging.warning('Could not start the monitoring daemon')


def extract_files(archive_path, target_dir):
    """
    Extract the given archive to the given directory, performing some checks.

    :param archive_path:
    :type archive_path:
    :param target_dir:
    :type target_dir:
    """
    target_dir = os.path.abspath(target_dir)
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
    with tarfile.open(archive_path, 'r') as tar_fh:
        # Check that names in the archive don't contain '..' and don't
        # start with '/'.
        for member in tar_fh.getmembers():
            abs_path = os.path.abspath(os.path.join(target_dir, member.path))
            if (not abs_path.startswith(target_dir) or
                not abs_path.startswith(SCION_ROOT)):
                raise Exception("Updater: unsafe filenames!")
            # Remove the top level directory from a member path
            member.path = os.sep.join(member.path.split(os.sep)[1:])
        logging.info('Extracting the archive...')
        tar_fh.extractall(target_dir)


def post_extract():
    """
    Run the post-extract procedures using the new (updated) updater.
    """
    logging.info('New (updated) updater: started, post-extract procedures.')
    start_monitoring_daemon()
    logging.info('Update: done.')


def run_updated_updater():
    """
    Launch the new (updated) updater in the same process. This function does not
    return.
    """
    logging.info('Calling the updated version...')
    executable = sys.executable
    args = sys.argv[:]
    args.insert(0, executable)
    args.append(IS_UPDATED_ARG)
    os.execvp(executable, args)


def update_package(archive_path, target_dir):
    """
    Update the SCION package using the provided distribution archive.

    :param archive_path:
    :type archive_path:
    :param target_dir:
    :type target_dir:
    """
    # Wait a bit, so the caller has some time to finish
    time.sleep(1)
    logging.info('Update: started.')
    stop_everything()
    extract_files(archive_path, target_dir)
    run_updated_updater()


def main():
    if len(sys.argv) < 3:
        sys.exit('Invalid number of arguments')
    logging.info("Updater main function: started.")
    archive_path = sys.argv[1]
    target_dir = sys.argv[2]
    update_package(archive_path, target_dir)


if __name__ == '__main__':
    init_logging(level=logging.INFO)
    if IS_UPDATED_ARG in sys.argv:
        post_extract()
    else:
        main()
