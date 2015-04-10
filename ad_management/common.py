import os
import xmlrpc.client

# Ports
MONITORING_DAEMON_PORT = 9000
SUPERVISORD_PORT = 9001

# Paths
SCION_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
MONITORING_DAEMON_DIR = os.path.join(SCION_ROOT, 'ad_management')
UPDATE_DIR_PATH = os.path.join(MONITORING_DAEMON_DIR, '.update_files')
UPDATE_SCRIPT_PATH = os.path.join(MONITORING_DAEMON_DIR, 'updater.py')
CERT_DIR_PATH = os.path.join(MONITORING_DAEMON_DIR, 'certs')
SUPERVISORD_PATH = os.path.join(SCION_ROOT, 'supervisor', 'supervisor.sh')
ARCHIVE_DIST_PATH = os.path.join(SCION_ROOT, 'dist')
WEB_SCION_DIR = os.path.join(SCION_ROOT, 'web_scion')

# Process names
MONITORING_DAEMON_PROC_NAME = 'monitoring_daemon'


def get_supervisor_server(host='localhost'):
    url = 'http://{}:{}/RPC2'.format(host, SUPERVISORD_PORT)
    return xmlrpc.client.ServerProxy(url)


def get_monitoring_server(host='localhost'):
    url = 'https://{}:{}/'.format(host, MONITORING_DAEMON_PORT)
    return xmlrpc.client.ServerProxy(url)


# Response wrappers for monitoring client/server

def response_success(*data):
    return [True] + list(data)


def get_data(response):
    return response[1]


def get_success_data(response):
    return get_data(response)


def response_failure(*errors):
    return [False] + list(errors)


def get_failure_errors(response):
    return get_data(response)


def is_success(response):
    assert isinstance(response[0], bool)
    return response[0]
