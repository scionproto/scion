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

# External
import capnp  # noqa

# SCION
import proto.ack_capnp as P
from lib.packet.packet_base import Cerealizable


class Ack(Cerealizable):
    """
    ACK packet.
    """
    NAME = "Ack"
    P_CLS = P.Ack

    @classmethod
    def from_values(cls, err_code, err_desc):
        return cls(cls.P_CLS.new_message(err=err_code, errDesc=err_desc))


def parse_ack(p):
    return Ack(p)
