#!/usr/bin/python3
# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`generator` --- SCION topology generator
=============================================
"""
# Stdlib
import argparse

# SCION
from lib.defines import (
    DEFAULT_SEGMENT_TTL,
    GEN_PATH,
)
from topology.config import (
    ConfigGenerator,
    DEFAULT_CERTIFICATE_SERVER,
    DEFAULT_SCIOND,
    DEFAULT_PATH_POLICY_FILE,
    DEFAULT_PATH_SERVER,
    DEFAULT_TOPOLOGY_FILE,
    DEFAULT_ZK_CONFIG,
    GENERATE_BIND_ADDRESS,
)


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-6', '--ipv6', action='store_true',
                        help='Generate IPv6 addresses')
    parser.add_argument('-c', '--topo-config', default=DEFAULT_TOPOLOGY_FILE,
                        help='Default topology config')
    parser.add_argument('-p', '--path-policy', default=DEFAULT_PATH_POLICY_FILE,
                        help='Path policy file')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help='Use Mininet to create a virtual network topology')
    parser.add_argument('-d', '--docker', action='store_true',
                        help='Create a docker-compose configuration')
    parser.add_argument('-n', '--network',
                        help='Network to create subnets in (E.g. "127.0.0.0/8"')
    parser.add_argument('-o', '--output-dir', default=GEN_PATH,
                        help='Output directory')
    parser.add_argument('-z', '--zk-config', default=DEFAULT_ZK_CONFIG,
                        help='Zookeeper configuration file')
    parser.add_argument('-b', '--bind-addr', default=GENERATE_BIND_ADDRESS,
                        help='Generate bind addresses (E.g. "192.168.0.0/16"')
    parser.add_argument('--pseg-ttl', type=int, default=DEFAULT_SEGMENT_TTL,
                        help='Path segment TTL (in seconds)')
    parser.add_argument('-cs', '--cert-server', default=DEFAULT_CERTIFICATE_SERVER,
                        help='Certificate Server implementation to use ("go" or "py")')
    parser.add_argument('-sd', '--sciond', default=DEFAULT_SCIOND,
                        help='SCIOND implementation to use ("go" or "py")')
    parser.add_argument('-ps', '--path-server', default=DEFAULT_PATH_SERVER,
                        help='Path Server implementation to use ("go or "py")')
    parser.add_argument('-ds', '--discovery', action='store_true',
                        help='Generate discovery service')
    args = parser.parse_args()
    confgen = ConfigGenerator(
        args.ipv6, args.output_dir, args.topo_config, args.path_policy, args.zk_config,
        args.network, args.mininet, args.docker, args.bind_addr, args.pseg_ttl, args.cert_server,
        args.sciond, args.path_server, args.discovery)
    confgen.generate_all()


if __name__ == "__main__":
    main()
