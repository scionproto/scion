# Copyright 2019 Anapaya Systems
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

import logging
from functools import wraps


class LogExec(object):
    def __init__(self, logger: logging.Logger, sub_command: str):
        self.sub_command = sub_command
        self.logger = logger

    def __call__(self, f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            self.logger.info("Start %s" % self.sub_command)
            ret = f(*args, **kwargs)
            if ret:
                self.logger.warning("Failed %s" % self.sub_command)
                return ret
            self.logger.info("Finished %s" % self.sub_command)
        return wrapper


def init_log():
    fmt = '%(asctime)-15s [%(levelname)-8s] %(message)s'
    logging.basicConfig(format=fmt, level='INFO')
