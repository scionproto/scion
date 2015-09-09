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
:mod:`common` --- AD management tool common definitions
=======================================================
"""
# Stdlib
import os

# SCION
from lib.defines import PROJECT_ROOT


# Ports
MANAGEMENT_DAEMON_PORT = 9010
SUPERVISORD_PORT = 9011

# Paths
MANAGEMENT_DAEMON_DIR = os.path.join(PROJECT_ROOT, 'ad_management')
UPDATE_DIR_PATH = os.path.join(MANAGEMENT_DAEMON_DIR, '.update_files')
PACKAGE_DIR_PATH = os.path.join(MANAGEMENT_DAEMON_DIR, '.packages')
UPDATE_SCRIPT_PATH = os.path.join(MANAGEMENT_DAEMON_DIR, 'updater.py')
CERT_DIR_PATH = os.path.join(MANAGEMENT_DAEMON_DIR, 'certs')
SUPERVISORD_PATH = os.path.join(PROJECT_ROOT, 'supervisor', 'supervisor.sh')
WEB_SCION_DIR = os.path.join(PROJECT_ROOT, 'web_scion')
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')

# Process names
MANAGEMENT_DAEMON_PROC_NAME = 'management_daemon'
