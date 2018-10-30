# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`cert` --- SCION topology certificate generator
=============================================
"""
# Stdlib
import base64
import os
from collections import defaultdict

# SCION
from lib.crypto.asymcrypto import (
    generate_enc_keypair,
    generate_sign_keypair,
    get_core_sig_key_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
)
from lib.crypto.certificate import Certificate
from lib.crypto.certificate_chain import CertificateChain, get_cert_chain_file_path
from lib.crypto.trc import (
    get_trc_file_path,
    OFFLINE_KEY_ALG_STRING,
    OFFLINE_KEY_STRING,
    ONLINE_KEY_ALG_STRING,
    ONLINE_KEY_STRING,
    TRC,
)
from lib.crypto.util import (
    get_offline_key_file_path,
    get_online_key_file_path,
)
from lib.errors import SCIONParseError
from topology.common import TopoID

INITIAL_CERT_VERSION = 1
INITIAL_TRC_VERSION = 1
INITIAL_GRACE_PERIOD = 0
MAX_QUORUM_CAS = 0
MAX_QUORUM_TRC = 4
THRESHOLD_EEPKI = 0

DEFAULT_TRC_VALIDITY = 365 * 24 * 60 * 60
DEFAULT_CORE_CERT_VALIDITY = 364 * 24 * 60 * 60
DEFAULT_LEAF_CERT_VALIDITY = 363 * 24 * 60 * 60

DEFAULT_KEYGEN_ALG = 'ed25519'


class CertGenerator(object):
    def __init__(self, topo_config, ca_certs):
        self.topo_config = topo_config
        self.core_count = defaultdict(int)
        self.ca_certs = ca_certs
        self.sig_priv_keys = {}
        self.sig_pub_keys = {}
        self.enc_priv_keys = {}
        self.enc_pub_keys = {}
        self.pub_online_root_keys = {}
        self.priv_online_root_keys = {}
        self.pub_offline_root_keys = {}
        self.priv_offline_root_keys = {}
        self.pub_core_sig_keys = {}
        self.priv_core_sig_keys = {}
        self.certs = {}
        self.core_certs = {}
        self.trcs = {}
        self.cert_files = defaultdict(dict)
        self.trc_files = defaultdict(dict)
        self.cust_files = defaultdict(dict)

    def generate(self):
        self._self_sign_keys()
        self._iterate(self._count_cores)
        self._iterate(self._gen_as_keys)
        self._iterate(self._gen_as_certs)
        self._build_chains()
        self._iterate(self._gen_trc_entry)
        self._iterate(self._sign_trc)
        self._iterate(self._gen_trc_files)
        return self.cert_files, self.trc_files, self.cust_files

    def _self_sign_keys(self):
        topo_id = TopoID.from_values(0, 0)
        self.sig_pub_keys[topo_id], self.sig_priv_keys[topo_id] = generate_sign_keypair()
        self.enc_pub_keys[topo_id], self.enc_priv_keys[topo_id] = generate_enc_keypair()

    def _iterate(self, f):
        for isd_as, as_conf in self.topo_config["ASes"].items():
            f(TopoID(isd_as), as_conf)

    def _count_cores(self, topo_id, as_conf):
        if self.is_core(as_conf):
            self.core_count[topo_id[0]] += 1

    def _gen_as_keys(self, topo_id, as_conf):
        sig_pub, sig_priv = generate_sign_keypair()
        enc_pub, enc_priv = generate_enc_keypair()
        self.sig_priv_keys[topo_id] = sig_priv
        self.sig_pub_keys[topo_id] = sig_pub
        self.enc_pub_keys[topo_id] = enc_pub
        self.enc_priv_keys[topo_id] = enc_priv
        sig_path = get_sig_key_file_path("")
        enc_path = get_enc_key_file_path("")
        self.cert_files[topo_id][sig_path] = base64.b64encode(sig_priv).decode()
        self.cert_files[topo_id][enc_path] = base64.b64encode(enc_priv).decode()
        if self.is_core(as_conf):
            # generate_sign_key_pair uses Ed25519
            on_root_pub, on_root_priv = generate_sign_keypair()
            off_root_pub, off_root_priv = generate_sign_keypair()
            core_sig_pub, core_sig_priv = generate_sign_keypair()
            self.pub_online_root_keys[topo_id] = on_root_pub
            self.priv_online_root_keys[topo_id] = on_root_priv
            self.pub_offline_root_keys[topo_id] = off_root_pub
            self.priv_offline_root_keys[topo_id] = off_root_priv
            self.pub_core_sig_keys[topo_id] = core_sig_pub
            self.priv_core_sig_keys[topo_id] = core_sig_priv
            online_key_path = get_online_key_file_path("")
            offline_key_path = get_offline_key_file_path("")
            core_sig_path = get_core_sig_key_file_path("")
            self.cert_files[topo_id][online_key_path] = base64.b64encode(on_root_priv).decode()
            self.cert_files[topo_id][offline_key_path] = base64.b64encode(off_root_priv).decode()
            self.cert_files[topo_id][core_sig_path] = base64.b64encode(core_sig_priv).decode()

    def _gen_as_certs(self, topo_id, as_conf):
        # Self-signed if cert_issuer is missing.
        issuer = TopoID(as_conf.get('cert_issuer', str(topo_id)))
        # Make sure that issuer is a core AS
        if issuer not in self.pub_online_root_keys:
            raise SCIONParseError("Certificate issuer is not a core AS: %s" % issuer)
        # Create core AS certificate
        if self.is_core(as_conf):
            signing_key = self.priv_online_root_keys[topo_id]
            can_issue = True
            comment = "Core AS Certificate"
            self.core_certs[topo_id] = Certificate.from_values(
                str(topo_id), str(issuer), INITIAL_TRC_VERSION, INITIAL_CERT_VERSION,
                comment, can_issue, DEFAULT_CORE_CERT_VALIDITY, self.enc_pub_keys[topo_id],
                self.pub_core_sig_keys[topo_id], signing_key
            )
        # Create regular AS certificate
        signing_key = self.priv_core_sig_keys[issuer]
        can_issue = False
        comment = "AS Certificate"
        self.certs[topo_id] = Certificate.from_values(
            str(topo_id), str(issuer), INITIAL_TRC_VERSION, INITIAL_CERT_VERSION,
            comment, can_issue, DEFAULT_LEAF_CERT_VALIDITY, self.enc_pub_keys[topo_id],
            self.sig_pub_keys[topo_id], signing_key
        )

    def _build_chains(self):
        for topo_id, cert in self.certs.items():
            chain = [cert]
            issuer = TopoID(cert.issuer)
            chain.append(self.core_certs[issuer])
            cert_path = get_cert_chain_file_path("", topo_id, INITIAL_CERT_VERSION)
            self.cert_files[topo_id][cert_path] = CertificateChain(chain).to_json()
            assert isinstance(topo_id, TopoID)
            map_path = os.path.join("customers", '%s-%s-V%d.key' % (
                topo_id.ISD(), topo_id.AS_file(), INITIAL_CERT_VERSION))
            self.cust_files[issuer][map_path] = base64.b64encode(
                self.sig_pub_keys[topo_id]).decode()

    def is_core(self, as_conf):
        return as_conf.get("core")

    def _gen_trc_entry(self, topo_id, as_conf):
        if not as_conf.get('core', False):
            return
        if topo_id[0] not in self.trcs:
            self._create_trc(topo_id[0])
        trc = self.trcs[topo_id[0]]
        # Add public root online/offline key to TRC

        trc.core_ases[str(topo_id)] = self._populate_core(topo_id)

    def _populate_core(self, topo_id):
        return {ONLINE_KEY_ALG_STRING: DEFAULT_KEYGEN_ALG,
                ONLINE_KEY_STRING: self.pub_online_root_keys[topo_id],
                OFFLINE_KEY_ALG_STRING: DEFAULT_KEYGEN_ALG,
                OFFLINE_KEY_STRING: self.pub_offline_root_keys[topo_id]}

    def _create_trc(self, isd):
        quorum_trc = min(self.core_count[isd], MAX_QUORUM_TRC)
        self.trcs[isd] = TRC.from_values(
            isd, "ISD %s" % isd, INITIAL_TRC_VERSION, {}, {}, {}, THRESHOLD_EEPKI, {}, quorum_trc,
            MAX_QUORUM_CAS, INITIAL_GRACE_PERIOD, False, {}, DEFAULT_TRC_VALIDITY)

    def _sign_trc(self, topo_id, as_conf):
        if not as_conf.get('core', False):
            return
        trc = self.trcs[topo_id[0]]
        trc.sign(topo_id, self.priv_online_root_keys[topo_id])

    def _gen_trc_files(self, topo_id, _):
        trc = self.trcs[topo_id[0]]
        trc_path = get_trc_file_path("", topo_id[0], INITIAL_TRC_VERSION)
        self.trc_files[topo_id][trc_path] = str(trc)
