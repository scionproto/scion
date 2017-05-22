# Copyright 2017 ETH Zurich
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
:mod:`util` --- DRKey util
============================

Util for DRKey Suite
"""
import datetime
import time


def drkey_time():
    return int(time.time())


def get_drkey_exp_time(prefetch=False):
    offset = 2 if prefetch else 1
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(offset)
    return int(exp_time.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
