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
import logging
import sys

# SCION
from lib.log import log_exception


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
