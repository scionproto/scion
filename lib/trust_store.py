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
:mod:`trust_store` --- Storage and management of trust objects (certs, TRCs).
=============================================================================
"""
# Stdlib
from collections import defaultdict
import glob
import os
import re

# External packages

# SCION
from lib.crypto.certificate import CertificateChain, TRC, verify_sig_chain_trc

CERT_DIR = 'certs'

class TrustStore(object):
    """
    Trust Store class.
    """

    def __init__(self, conf_dir):
        self._dir = "%s/%s" % (conf_dir, CERT_DIR)
        # cert_chain_file = self.get_cert_chain_file_path(
        #     self.conf_dir, self.topology.isd_id, self.topology.ad_id,
        #     self.config.cert_ver)
        # self.cert_chain = CertificateChain(cert_chain_file)
        self._certs = defaultdict(list)
        self._trcs = defaultdict(list) 
        self._init_trcs()
        self._init_certs()

    def _init_trcs(self):
        # trc_ver_path = {}  # Temporarily keep ISD: (TRC_VER, PATH) 
        for path in glob.glob("%s/*.trc" % self._dir):
            isd, ver = re.findall("\d+", path)[-2:]
            self._trcs[isd].append((ver, TRC(path)))
            # Determine the latest TRC per ISD.
        #     if isd not in trc_ver_path or trc_ver[isd][0] < ver:
        #         trc_ver_path[isd] = (ver, path)
        # # Load the latest TRCs. 
        # for isd in trc_ver_path:
        #     self._trcs[isd] = Trc(ReadFile(trc_ver_path[isd][1]))  # TODO 

    def _init_certs(self):
        for path in glob.glob("%s/*.crt" % self._dir):
            isd, ad, ver = re.findall("\d+", path)[-3:]
            self._certs[(isd, ad)].append((ver, CertificateChain(path)))

    def get_trc(isd, version=None):
        if not self._trcs[isd]:
            return None
        if version is None:  # Return latest TRC.
            _, trc = sorted(self._trcs[isd])[-1]
            return trc
        else:  # Try to find a TRC with given version.
            for ver, trc in self._trcs[isd]:
                if version == ver:
                    return trc
        return None

    def get_cert(isd, ad, version=None):
        if not self._certs[(isd, ad)]:
            return None
        if version is None:  # Return latest cert.
            _, cert = sorted(self._certs[(isd, ad)])[-1]
            return cert
        else:  # Try to find a cert with given version.
            for ver, cert in self._certs[(isd, ad)]:
                if version == ver:
                    return cert

    def get_cert_chain_file_path(conf_dir, isd_id, ad_id,
                                 version):  # pragma: no cover
        """
        Return the certificate chain file path for a given ISD.
        """
        return os.path.join(conf_dir, CERT_DIR,
                            'ISD%s-AD%s-V%s.crt' % (isd_id, ad_id, version))

    def get_trc_file_path(conf_dir, isd_id, version):  # pragma: no cover
        """
        Return the TRC file path for a given ISD.
        """
        return os.path.join(conf_dir, CERT_DIR,
                            'ISD%s-V%s.crt' % (isd_id, version))

    def get_sig_key_file_path(conf_dir):  # pragma: no cover
        """
        Return the signing key file path.
        """
        return os.path.join(conf_dir, KEYS_DIR, "ad-sig.key")


