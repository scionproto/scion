import os
import xmlrpc.client

# Ports
MONITORING_DAEMON_PORT = 9000
SUPERVISORD_PORT = 9001


def get_supervisor_server():
    url = 'http://localhost:{}/RPC2'.format(SUPERVISORD_PORT)
    return xmlrpc.client.ServerProxy(url)


def get_monitoring_server(host='localhost'):
    url = 'https://{}:{}/'.format(host, MONITORING_DAEMON_PORT)
    return xmlrpc.client.ServerProxy(url)


### Responses for monitoring client/server

def response_success(*data):
    return [True] + list(data)


def get_success_data(response):
    return response[1]


def response_failure(*errors):
    return [False] + list(errors)


def get_failure_errors(response):
    return response[1]


def is_success(response):
    return response[0]


### Paths

SCION_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
UPDATE_DIR = os.path.join(SCION_ROOT, 'daemon_monitor/.update_files/')
UPDATE_SCRIPT_PATH = os.path.join(SCION_ROOT, 'daemon_monitor/updater.py')
SUPERVISORD_PATH = os.path.join(SCION_ROOT, 'supervisor/supervisor.sh')

# Process names
MONITORING_DAEMON_PROC_NAME = 'monitoring_daemon'