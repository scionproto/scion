#!/usr/bin/python3
# Copyright 2018 ETH Zurich
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

# Stdlib
import os
import argparse
from ipaddress import IPv6Address, IPv6Network

# SCION
from lib.defines import (
    GEN_PATH,
    DEFAULT6_CLIENT,
    DEFAULT6_MASK,
    DEFAULT6_NETWORK,
    DEFAULT6_SERVER,
    NETWORKS_FILE,
    OVERLAY_FILE,
)

from lib.util import (
    read_file,
)


def set_interfaces():
    path = os.path.join(GEN_PATH, NETWORKS_FILE)
    with open(path, 'r') as f:
        for l in f.readlines():
            try:
                address = l.split("= ")[1]
                addr = IPv6Address(address[:-1])
                if addr in IPv6Network(DEFAULT6_NETWORK):
                    os.system('sudo ip addr replace %s/104 dev lo' % (str(addr)))
            except Exception:
                continue


def get_overlay():
    file_path = os.path.join(GEN_PATH, OVERLAY_FILE)
    return read_file(file_path).strip()


def main():
    overlay = get_overlay()
    if overlay == 'UDP/IPv4' or overlay == 'IPv4':
        return

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--add', action='store_true',
                        help='Add IPv6 local host addresses to loopback')
    parser.add_argument('-d', '--delete', action='store_true',
                        help='Delete IPv6 local host addresses from loopback')
    args = parser.parse_args()
    if args.add:
        os.system('sudo ip addr replace %s dev lo' % (DEFAULT6_CLIENT + DEFAULT6_MASK))
        os.system('sudo ip addr replace %s dev lo' % (DEFAULT6_SERVER + DEFAULT6_MASK))
        set_interfaces()
    if args.delete:
        os.system('sudo ip addr flush dev lo to %s' % (DEFAULT6_NETWORK))

if __name__ == "__main__":
    main()
