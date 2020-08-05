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
    GEN_PATH,
)
from topology.config import (
    ConfigGenerator,
    ConfigGenArgs,
    DEFAULT_TOPOLOGY_FILE,
)


def add_arguments(parser):
    parser.add_argument('-c', '--topo-config', default=DEFAULT_TOPOLOGY_FILE,
                        help='Path policy file')
    parser.add_argument('-d', '--docker', action='store_true',
                        help='Create a docker-compose configuration')
    parser.add_argument('-n', '--network',
                        help='Network to create subnets in (E.g. "127.0.0.0/8"')
    parser.add_argument('-o', '--output-dir', default=GEN_PATH,
                        help='Output directory')
    parser.add_argument('-f', '--svcfrac', type=float, default=0.4,
                        help='Attempt SVC resolution in RPC calls for a fraction of\
                        available timeout')
    parser.add_argument('--random-ifids', action='store_true',
                        help='Generate random IFIDs')
    parser.add_argument('--docker-registry', help='Specify docker registry to pull images from')
    parser.add_argument('--image-tag', help='Docker image tag')
    parser.add_argument('--sig', action='store_true',
                        help='Generate a SIG per AS (only available with -d, the SIG image needs\
                        to be built manually e.g. when running acceptance tests)')
    parser.add_argument('-qos', '--colibri', action='store_true',
                        help='Generate COLIBRI service')
    return parser


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = ConfigGenArgs(parser.parse_args())
    confgen = ConfigGenerator(args)
    confgen.generate_all()


if __name__ == "__main__":
    main()
