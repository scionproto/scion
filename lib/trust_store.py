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
:mod:`trust_store` --- Storage and management of trust objects (TRCs and certs).
================================================================================
"""
# Stdlib
from collections import defaultdict
import glob
import logging

# SCION
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.trc import TRC
from lib.util import CERT_DIR, read_file, write_file


class TrustStore(object):
    """Trust Store class."""
    def __init__(self, conf_dir):  # pragma: no cover
        self._dir = "%s/%s" % (conf_dir, CERT_DIR)
        self._certs = defaultdict(list)
        self._trcs = defaultdict(list)
        self._init_trcs()
        self._init_certs()

    def _init_trcs(self):  # pragma: no cover
        for path in glob.glob("%s/*.trc" % self._dir):
            trc_raw = read_file(path)
            self.add_trc(TRC.from_raw(trc_raw), write=False)
            logging.debug("Loaded: %s" % path)

    def _init_certs(self):  # pragma: no cover
        for path in glob.glob("%s/*.crt" % self._dir):
            cert_raw = read_file(path)
            self.add_cert(CertificateChain.from_raw(cert_raw), write=False)
            logging.debug("Loaded: %s" % path)

    def get_trc(self, isd, version=None):
        if not self._trcs[isd]:
            return None
        if version is None:  # Return the most recent TRC.
            _, trc = sorted(self._trcs[isd])[-1]
            return trc
        else:  # Try to find a TRC with given version.
            for ver, trc in self._trcs[isd]:
                if version == ver:
                    return trc
        return None

    def get_trcs(self):  # pragma: no cover
        # Return list of the most recent TRCs.
        res = []
        for isd in self._trcs:
            res.append(self.get_trc(isd))
        return res

    def get_cert(self, isd_as, version=None):
        if not self._certs[isd_as]:
            return None
        if version is None:  # Return the most recent cert.
            _, cert = sorted(self._certs[isd_as])[-1]
            return cert
        else:  # Try to find a cert with given version.
            for ver, cert in self._certs[isd_as]:
                if version == ver:
                    return cert
        return None

    def add_trc(self, trc, write=True):
        isd, version = trc.get_isd_ver()
        for ver, _ in self._trcs[isd]:
            if version == ver:
                return
        self._trcs[isd].append((version, trc))
        if write:
            write_file("%s/ISD%s-V%s.trc" % (self._dir, isd, version), str(trc))

    def add_cert(self, cert, write=True):
        isd_as, version = cert.get_leaf_isd_as_ver()
        for ver, _ in self._certs[isd_as]:
            if version == ver:
                return
        self._certs[isd_as].append((version, cert))
        if write:
            write_file("%s/ISD%s-AS%s-V%s.crt" %
                       (self._dir, isd_as[0], isd_as[1], version),
                       str(cert))
