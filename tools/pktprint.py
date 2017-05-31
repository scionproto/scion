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
:mod:`pktprint` --- Packet printing utility
============================================
A very simple utility to parse a hex-encoded scion packet and pretty-print it.
"""

# Stdlib
import argparse

# SCION
import lib.packet.scion

parser = argparse.ArgumentParser()
parser.add_argument("raw", metavar='RAW', nargs='+',
                    help="hex-encoded raw packet (whitespace is ignored)")
parser.add_argument("--ctrl", action="store_true", help="Parse a SCION control payload")
args = parser.parse_args()

hexes = bytes.fromhex("".join(args.raw))
p = lib.packet.scion.SCIONL4Packet(hexes)
print("=============> Packet:\n%s" % p)
print("=============> Validate: %s" % p.validate(len(hexes)))
if args.ctrl:
    print("=============> SCION control payload:\n: %s" % p.parse_payload())
