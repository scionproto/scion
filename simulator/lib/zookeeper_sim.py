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
:mod:`zookeeper_sim` --- Zookeeper(simulator)
=============================================
"""


class ZookeeperSim(object):
    """
    Zookeeper does not run in simulator.
    """
    def __init__(self):
        pass

    def is_connected(self):
        return True

    def have_lock(self):
        return True


class ZkSharedCacheSim(object):
    """
    Zookeeper does not run in simulator.
    """
    def __init__(self):
        pass

    def store(self, name, value):
        pass

    def expire(self, ttl):
        pass
