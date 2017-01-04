#!/usr/bin/python3

import sys
import lib.packet.scion

raw = "".join(sys.argv[1].split())[4:]
hexes = bytes.fromhex(raw)
p = lib.packet.scion.SCIONL4Packet(hexes)
print("=============> Packet:\n%s" % p)
print("=============> Validate: %s" % p.validate(len(hexes)))
print("=============> Payload:\n%s" % p.parse_payload())
