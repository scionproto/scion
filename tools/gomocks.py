#!/usr/bin/python3
# Copyright 2019 ETH Zurich
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
:mod: 'gomocks' --- Helper script to regenerate go mock files.
==============================================================
"""

import os.path

from plumbum.cmd import mockgen,mkdir

MOCK_TARGETS= [
        ("net", "Addr,Conn,PacketConn"),
        ("github.com/scionproto/scion/go/lib/snet", "Conn,Network"),
        ("github.com/scionproto/scion/go/lib/snet/snetproxy", "IOOperation,Reconnecter"),
        ("github.com/scionproto/scion/go/lib/snet/internal/ctxmonitor", "Monitor"),
        ("github.com/scionproto/scion/go/lib/snet/internal/pathsource", "PathSource"),
        ("github.com/scionproto/scion/go/lib/pathmgr", "Querier,Resolver"),
        ("github.com/scionproto/scion/go/lib/pathdb", "PathDB,Transaction,ReadWrite"),
        ("github.com/scionproto/scion/go/lib/l4", "L4Header"),
        ("github.com/scionproto/scion/go/lib/infra", "TrustStore,Messenger,ResponseWriter"),
        ("github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb", "TrustDB"),
        ("github.com/scionproto/scion/go/lib/sciond", "Service,Connector"),
        ("github.com/scionproto/scion/go/lib/log", "Handler,Logger"),
        ("github.com/scionproto/scion/go/lib/revcache", "RevCache"),
]

# Directory for standard library mocks
STD_LIB_MOCKS_DIRECTORY = os.path.join("go", "lib", "mocks")

# Prefix of SCION packages
SCION_PACKAGE_PREFIX = "github.com/scionproto/scion"

def main():
    for (package, interfaces) in MOCK_TARGETS:
        (mock_dir, mock_file) = get_mock_file_path(package)

        mkdir("-p", mock_dir)
        (mockgen[package, interfaces] > mock_file)()
        print("Generated mocks for %s (%s)" % (package, interfaces))

def get_mock_file_path(package):
    mock_parent_dir = get_relative_path(package)
    package_name = os.path.basename(mock_parent_dir)

    mock_dir = os.path.join(mock_parent_dir, "mock_" + package_name)
    mock_file = os.path.join(mock_dir, package_name + ".go")
    return (mock_dir, mock_file)

def get_relative_path(target_package):
    if is_scion_package(target_package):
        return strip_scion_package_prefix(target_package)
    return os.path.join(STD_LIB_MOCKS_DIRECTORY, target_package)

def is_scion_package(target_package):
     return os.path.commonpath([SCION_PACKAGE_PREFIX, target_package]) == SCION_PACKAGE_PREFIX

def strip_scion_package_prefix(target_package):
     return target_package[len(SCION_PACKAGE_PREFIX)+1:]

if __name__ == "__main__":
    main()

