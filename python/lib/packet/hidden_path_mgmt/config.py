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
:mod:`hidden_path` --- Base class for Hidden path packets
=========================================================
"""
# External
import capnp  # noqa

# SCION
import proto.hidden_path_mgmt_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS


class HiddenPathConfigId(Cerealizable):
    NAME = "HPCfgId"
    P_CLS = P.HPCfgId
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, master_ia, config_id):
        p = cls.P_CLS.new_message(masterIA=master_ia.pack())
        p.cfgId = config_id
        return cls(p)

    def master_ia(self):
        return ISD_AS(self.p.masterIA)

    def config_id(self):
        return self.p.cfgId


class HiddenPathConfig(Cerealizable):
    NAME = "HPCfg"
    P_CLS = P.HPCfg
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, id, version, hps_ias, writer_ias, reader_ias):
        p = cls.P_CLS.new_message(id=id.p, version=version)
        p.init("hpIAs", len(hps_ias))
        for i, hps_ia in enumerate(hps_ias):
            p.hpIAs[i] = int(hps_ia)
        p.init("writeIAs", len(writer_ias))
        for i, writer_ia in enumerate(writer_ias):
            p.writeIAs[i] = int(writer_ia)
        p.init("readIAs", len(reader_ias))
        for i, reader_ia in enumerate(reader_ias):
            p.readIAs[i] = int(reader_ia)

        return cls(p)

    def id(self):
        return HiddenPathConfigId(self.p.id)

    def version(self):
        return self.p.version

    def hps_ia(self, idx):
        return ISD_AS(self.p.hpIAs[idx])

    def iter_hps_ias(self, start=0):
        for i in range(start, len(self.p.hpIAs)):
            yield self.hps_ia(i)

    def writer_ia(self, idx):
        return ISD_AS(self.p.writeIAs[idx])

    def iter_writer_ias(self, start=0):
        for i in range(start, len(self.p.writeIAs)):
            yield self.writer_ia(i)

    def reader_ia(self, idx):
        return ISD_AS(self.p.readIAs[idx])

    def iter_reader_ias(self, start=0):
        for i in range(start, len(self.p.readIAs)):
            yield self.reader_ia(i)
