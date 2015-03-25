import os
import tarfile
import logging
from daemon_monitor.common import get_supervisor_server, UPDATE_DIR

ARCHIVE_FILE = 'scion-0.1.0.tar.gz'

# Stop everything
def stop_everything():
    logging.warning('Stopping all processes...')
    server = get_supervisor_server()
    server.supervisor.stopAllProcesses()


# Restart everything
def start_everything():
    logging.warning('Starting all processes...')
    server = get_supervisor_server()
    server.supervisor.startAllProcesses()


def extract_files():
    archive_path = UPDATE_DIR + ARCHIVE_FILE
    target_dir = UPDATE_DIR
    with tarfile.open(archive_path, 'r') as tar_fh:
        # Check that names in the archive don't contain '..' and don't
        # start with '/'.
        for member in tar_fh.getmembers():
            abs_path = os.path.abspath(os.path.join(target_dir, member.path))
            if not abs_path.startswith(target_dir):
                raise Exception("Updater: unsafe filenames!")
        logging.warning('Extracting the archive...')
        tar_fh.extractall(target_dir)


def update_package():
    logging.warning('Update: started.')
    stop_everything()
    extract_files()
    start_everything()
    logging.warning('Update: done.')


if __name__ == '__main__':
    update_package()

