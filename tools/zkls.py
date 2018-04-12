#!/usr/bin/python3
# Copyright 2016 ETH Zurich
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
:mod:`zkls` --- Small utility to list the contents of zookeeper.
================================================================
E.g.: `./tools/zkls.py -s 127.0.0.91:4006 -p 1-ff00:0:312/ps/path_cache`
"""

# Stdlib
import argparse
import os

# External packages
from kazoo.client import KazooClient


def print_dir(zk, dir_):
    print(dir_)
    for entries in sorted(zk.get_children(dir_)):
        print_dir(zk, os.path.join(dir_, entries))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--server", default="127.0.0.1:2181",
                        help="Zookeeper server to connect to. (Default: %(default)s)")
    parser.add_argument(
        "-p", "--path", default="/",
        help="Zookeeper path to list contents of, recursively. (Default: %(default)s)")
    args = parser.parse_args()
    zk = KazooClient(hosts=args.server)
    zk.start()
    print_dir(zk, args.path)

if __name__ == '__main__':
    main()
