#!/usr/bin/env python3
import os
import sys
import tarfile
import logging
import time
import subprocess
import xmlrpc.client
from daemon_monitor.common import (get_supervisor_server,
                                   MONITORING_DAEMON_PROC_NAME,
                                   SUPERVISORD_PATH, SCION_ROOT)
from lib.util import init_logging

THIS_SCRIPT_PATH = os.path.abspath(__file__)
THIS_SCRIPT_DIR = os.path.dirname(THIS_SCRIPT_PATH)
THIS_SCRIPT_NAME = os.path.basename(THIS_SCRIPT_PATH)

IS_UPDATED_ARG = '--new'


# Stop everything
def stop_everything():
    logging.info('Stopping all processes...')
    server = get_supervisor_server()
    try:
        server.supervisor.stopAllProcesses()
    except (ConnectionRefusedError, xmlrpc.client.Fault) as ex:
        logging.warning('Couldn\'t stop processes')


# Restart everything
def start_everything():
    logging.info('Starting all processes...')
    server = get_supervisor_server()
    try:
        server.supervisor.startAllProcesses()
    except (ConnectionRefusedError, xmlrpc.client.Fault) as ex:
        logging.warning('Couldn\'t start processes')


def start_monitoring_daemon():
    # First, try to start 'supervisor' if not started
    exit_status = subprocess.call([SUPERVISORD_PATH, 'status'],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
    logging.info('Supervisord exit status: {}'.format(exit_status))

    # Second, perform an API call
    logging.info('Starting the monitoring daemon...')
    server = get_supervisor_server()
    try:
        server.supervisor.startProcess(MONITORING_DAEMON_PROC_NAME)
    except (ConnectionRefusedError, xmlrpc.client.Fault) as ex:
        logging.warning('Couldn\'t start monitoring daemon')


def extract_files(archive_path, target_dir):
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
    target_dir = os.path.abspath(target_dir)
    with tarfile.open(archive_path, 'r') as tar_fh:
        # Check that names in the archive don't contain '..' and don't
        # start with '/'.
        for member in tar_fh.getmembers():
            abs_path = os.path.abspath(os.path.join(target_dir, member.path))
            if (not abs_path.startswith(target_dir) or
                not abs_path.startswith(SCION_ROOT)):
                raise Exception("Updater: unsafe filenames!")
            # Remove the top leve directory from the member path
            member.path = os.sep.join(member.path.split(os.sep)[1:])
        logging.info('Extracting the archive...')
        tar_fh.extractall(target_dir)


def post_extract():
    # Run the post-extract procedures using the new (updated) updater
    logging.info('New (updated) updater: started, post-extract procedures.')
    start_monitoring_daemon()
    logging.info('Update: done.')


def run_updated_updater():
    """Does not return"""
    logging.info('Calling the updated version...')
    executable = sys.executable
    args = sys.argv[:]
    args.insert(0, executable)
    args.append(IS_UPDATED_ARG)
    os.execvp(executable, args)


def update_package(archive_path, target_dir):
    # Wait a bit, so the caller has some time to finish
    time.sleep(1)
    logging.info('Update: started.')
    stop_everything()
    extract_files(archive_path, target_dir)
    # start_everything()
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
