"""
dummy_host.py

Copyright 2015 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from lib.packet.host_addr import IPv4HostAddr
import logging
import sys

from endhost.sciond import SCIONDaemon


def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 3:
        print("Usage: %s IP topo_file", sys.argv[0])
        sys.exit()

    sd = SCIONDaemon.start(IPv4HostAddr(sys.argv[1]), sys.argv[2])

    paths = sd.get_paths(2, 26)
    print("Received %d paths:\n%s" % (len(paths), paths))
    sys.exit()

if __name__ == "__main__":
    main()
