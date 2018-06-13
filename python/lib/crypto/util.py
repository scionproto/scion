# Copyright 2017 ETH Zurich
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
:mod:`util` --- SCION crypto utilities
===============================

Various utilities for SCION functionality.
"""
# Stdlib
import os

CERT_DIR = 'certs'
KEYS_DIR = 'keys'


def get_online_key_file_path(conf_dir):
    """
    Return the online key file path.
    """
    return os.path.join(conf_dir, KEYS_DIR, "online-root.seed")


def get_offline_key_file_path(conf_dir):
    """
    Return the offline key file path.
    """
    return os.path.join(conf_dir, KEYS_DIR, "offline-root.seed")


def get_ca_private_key_file_path(conf_dir, name):
    """
    Return the ca private key file path
    """
    return os.path.join(conf_dir, "%s.key" % name)


def get_ca_cert_file_path(conf_dir, name):
    """
    Return the ca certificate file path
    """
    return os.path.join(conf_dir, "%s.cert" % name)
