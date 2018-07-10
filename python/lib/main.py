# Copyright 2015 ETH Zurich
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
:mod:`main` --- Main functions for SCION
========================================
"""
# Stdlib
import argparse
import logging
import os
import sys

# SCION
from lib.app.sciond import get_default_sciond_path
from lib.defines import TOPO_FILE
from lib.log import init_logging, log_exception
from lib.topology import Topology
from lib.util import handle_signals, trace


def main_wrapper(main, *args, **kwargs):
    """
    Run the supplied function with any args and kwargs specified, catching any
    raised exceptions and dealing with them appropriately.
    """
    try:
        main(*args, **kwargs)
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)


def main_default(type_, local_type=None, trace_=False, **kwargs):
    """
    Default main() method. Parses cmdline args, setups up signal handling,
    logging, creates the appropriate object and runs it.

    :param type type_: Primary type to instantiate.
    :param type local_type:
        If not `None`, load the topology to check if this is a core or local AS.
        If it's a core AS, instantiate the primary type, otherwise the local
        type.
    :param bool trace_: Should a periodic thread stacktrace report be created?
    """
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('--log_dir', default="logs/", help='Log dir (Default: logs/)')
    parser.add_argument('--spki_cache_dir', default="gen-cache/",
                        help='Cache dir for SCION TRCs and cert chains (Default: gen-cache/)')
    parser.add_argument('--prom', type=str, help='Address to export prometheus metrics on')
    parser.add_argument('--sciond_path', type=str, help='Sciond socket path '
                        '(Default: %s)' % get_default_sciond_path())
    parser.add_argument('server_id', help='Server identifier')
    parser.add_argument('conf_dir', nargs='?', default='.',
                        help='Configuration directory (Default: ./)')
    args = parser.parse_args()
    init_logging(os.path.join(args.log_dir, args.server_id))

    if local_type is None:
        inst = type_(args.server_id, args.conf_dir, prom_export=args.prom,
                     sciond_path=args.sciond_path,
                     spki_cache_dir=args.spki_cache_dir, **kwargs)
    else:
        # Load the topology to check if this is a core AD or not
        topo = Topology.from_file(os.path.join(args.conf_dir, TOPO_FILE))
        if topo.is_core_as:
            inst = type_(args.server_id, args.conf_dir, prom_export=args.prom,
                         sciond_path=args.sciond_path,
                         spki_cache_dir=args.spki_cache_dir, **kwargs)
        else:
            inst = local_type(args.server_id, args.conf_dir,
                              prom_export=args.prom,
                              sciond_path=args.sciond_path,
                              spki_cache_dir=args.spki_cache_dir, **kwargs)
    if trace_:
        trace(inst.id)
    logging.info("Started %s", args.server_id)
    inst.run()
