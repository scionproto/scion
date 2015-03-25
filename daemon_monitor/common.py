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

# Paths
SCION_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
UPDATE_DIR = SCION_ROOT + '/daemon_monitor/.update_files/'

# Proces names
MONITORING_DAEMON_PROC_NAME = 'monitoring_daemon'