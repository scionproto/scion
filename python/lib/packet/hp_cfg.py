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
:mod:`hp_cfg` --- Container for hidden path config related packets
===============================================================
"""
# External
import capnp  # noqa

# SCION
import proto.hp_cfg_capnp as P
from lib.errors import SCIONSigVerError
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.util import proto_len


class HPCfgId(Cerealizable):
    NAME = "HPCfgId"
    P_CLS = P.HPCfgId

    @classmethod
    def from_values(cls, master_ia, cfg_id):
        """
        :param master_ia scion_addr.ISD_AS: The master IA part of the config ID.
        :param cfg_id int: An 8 byte integer.
        """
        p = cls.P_CLS.new_message(masterIA=master_ia.pack(), cfgId=cfg_id)
        return cls(p)

    def master_ia(self):
        return ISD_AS(self.p.masterIA)

    def short_desc(self):
        return "%s | %d" % (self.master_ia(), self.p.cfgId)


class HPCfg(Cerealizable):  # pragma: no cover
    NAME = "HPCfg"
    P_CLS = P.HPCfg
    VER = proto_len(P.HPCfg.schema) - 1

    @classmethod
    def from_values(cls, id, ver, hps_ias, writer_ias, reader_ias):
        p = cls.P_CLS.new_message(id=id.p, version=ver)
        p.init("hpsIAs", len(hps_ias))
        for i, hps_ia in enumerate(hps_ias):
            p.hpIAs[i] = hps_ia.pack()
        p.init("writerIAs", len(writer_ias))
        for i, writer_ia in enumerate(writer_ias):
            p.writeIAs[i] = writer_ia.pack()
        p.init("readerIAs", len(reader_ias))
        for i, reader_ia in enumerate(reader_ias):
            p.readIAs[i] = reader_ia.pack()

        return cls(p)

    def version(self):
        return self.p.version

    def id(self):
        return HPCfgId(self.p.id)

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

    def sig_pack(self):
        if self.VER != 4:
            raise SCIONSigVerError("HPCfg.sig_pack cannot support version %s",
                                   self.VER)
        b = []
        b.append(self.id().sig_pack())
        b.append(self.version().to_bytes(8, 'big'))
        for hps_ia in self.iter_hps_ias():
            b.append(hps_ia.pack())
        for writer_ia in self.iter_writer_ias():
            b.append(writer_ia.pack())
        for reader_ia in self.iter_reader_ias():
            b.append(reader_ia.pack())
        return b"".join(b)

    def short_desc(self):
        d = []
        d.append(self.id().short_desc())
        hps_ias = []
        for hps_ia in self.iter_hps_ias():
            hps_ias.append(hps_ia)
        d.append("   HPS %s" % ", ".join(hps_ias))
        writer_ias = []
        for writer_ia in self.iter_writer_ias():
            writer_ias.append(writer_ia)
        d.append("   Writer ASes %s" % ", ".join(writer_ias))
        reader_ias = []
        for reader_ia in self.iter_reader_ias():
            reader_ias.append(reader_ia)
        d.append("   Reader ASes %s" % ", ".join(reader_ias))
        return "\n".join(d)
