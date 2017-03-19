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
:mod:`missing_trc_cert_map` --- SCION map for missing trcs and certchains
===============================================
"""


class PathSegMeta(object):
    """
    TODO(Sezer): change description
    The MissingTrcCertMap class holds missing trcs and certificates
    for a scion element instance.
    """

    def __init__(self, seg, meta=None, type_=None, params=None, from_zk=False):
        self.trc_vers, self.cert_vers = seg.get_trcs_certs()
        self.missing_trcs = set()
        self.missing_certs = set()
        self.seg = seg
        self.meta = meta
        self.type_ = type_
        self.params = params
        self.from_zk = from_zk

    def verifiable(self):
        return not self.missing_trcs and not self.missing_certs
