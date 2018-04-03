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
    NETWORKS_FILE,
)


def set_interfaces(action):
    path = os.path.join(GEN_PATH, NETWORKS_FILE)
    with open(path, 'r') as f:
        for l in f.readlines():
            try:
                address = l.split("= ")[1]
                addr = IPv6Address(address[:-1])
                if addr in IPv6Network('::127:0:0:0/112'):
                    # Redirect stderr to NULL to avoid error in case the IP address is alredy set
                    os.system('ip addr %s %s/128 dev lo 2>/dev/null' % (action, str(addr)))
            except Exception:
                continue


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--add', action='store_true',
                        help='Add IPv6 local host addresses to loopback')
    parser.add_argument('-d', '--delete', action='store_true',
                        help='Delete IPv6 local host addresses from loopback')
    args = parser.parse_args()
    if args.add:
        set_interfaces('add')
    if args.delete:
        set_interfaces('delete')

if __name__ == "__main__":
    main()
