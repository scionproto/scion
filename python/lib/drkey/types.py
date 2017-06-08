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
:mod:`types` --- DRKey types
============================

For all type classes used in DRKey
"""

###########################
# DRKey types
###########################


class DRKeySecretValue(object):
    """ DRKey secret value. """

    def __init__(self, secret, exp_time):
        self.secret = secret
        self.exp_time = exp_time

    def tuple(self):
        return self.exp_time,


class BaseDRKey(object):
    """ Base for first order and protocol DRKey. """

    def tuple(self):
        raise NotImplementedError

    def __hash__(self):
        return hash(self.tuple())

    def __eq__(self, other):
        return self.tuple() == other.tuple()

    def __ne__(self, other):
        return not (self == other)


class FirstOrderDRKey(BaseDRKey):
    """ First order DRKey. """

    def __init__(self, src_ia, dst_ia, exp_time=None, drkey=None):
        """
        Create first order DRKey (src_ia -> dst_ia).

        :param ISD_AS src_ia: source ISD-AS of the DRKey.
        :param ISD_AS dst_ia: destination ISD-AS of the DRKey.
        :param int exp_time: expiration time of the DRKey (format: drkey_time())
        :param bytes drkey: the raw DRKey.
        """
        self.src_ia = src_ia
        self.dst_ia = dst_ia
        self.drkey = drkey
        self.exp_time = exp_time

    def tuple(self):
        return self.src_ia, self.dst_ia, self.exp_time

    def __str__(self):
        drkey = self.drkey.hex() if self.drkey else "None"
        return "FirstOrderDRKey (%s->%s): %s expires %s" % (
            self.src_ia, self.dst_ia, drkey, self.exp_time
        )
