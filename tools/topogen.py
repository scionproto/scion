#!/usr/bin/env python3
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
:mod:`topogen` --- SCION topology generator
=============================================
"""
# Stdlib
import argparse

# SCION
from topology.defines import (
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
                        help='Create a docker compose configuration')
    parser.add_argument('-n', '--network',
                        help='IPv4 network to create subnets in (E.g. "127.0.0.0/8"')
    parser.add_argument('-n6', '--network-v6',
                        help='IPv6 network to create subnets in (E.g. "fd00:f00d:cafe::7f00:0000/104"')
    parser.add_argument('-o', '--output-dir', default=GEN_PATH,
                        help='Output directory')
    parser.add_argument('-t', '--topology-jsons-only', action='store_true',
                        help='Create only topology.json files')
    parser.add_argument('--random-ifids', action='store_true',
                        help='Generate random IFIDs')
    parser.add_argument('--docker-registry', help='Specify docker registry to pull images from',
                        default='scion')
    parser.add_argument('--image-tag', help='Docker image tag',
                        default='latest')
    parser.add_argument('--sig', action='store_true',
                        help='Generate a SIG per AS (only available with -d, the SIG image needs\
                        to be built manually e.g. when running acceptance tests)')
    parser.add_argument('--features', help='Feature flags to enable, a comma separated list\
                        e.g. foo,bar enables foo and bar feature.')
    return parser


def init_features(raw_args):
    features = getattr(raw_args, 'features')
    if features is None:
        features = ''
    feature_dict = {}
    for f in features.split(','):
        if f != '':
            feature_dict[f] = True
    setattr(raw_args, 'features', feature_dict)


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    raw_args = parser.parse_args()
    init_features(raw_args)
    args = ConfigGenArgs(raw_args)
    confgen = ConfigGenerator(args)
    confgen.generate_all()


if __name__ == "__main__":
    main()
