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
import os
import threading

# External packages
from prometheus_client import Gauge

# SCION
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.trc import TRC
from lib.crypto.util import CERT_DIR
from lib.util import read_file, write_file


TRCS_TOTAL = Gauge("ts_trcs_total", "# of TRCs in TrustStore", ["server_id", "isd_as"])
CERTS_TOTAL = Gauge("ts_certs_total", "# of Certs in TrustStore", ["server_id", "isd_as"])


class TrustStore(object):
    """Trust Store class."""
    def __init__(self, conf_dir, cache_dir, ename, labels=None):  # pragma: no cover
        """
        :param str conf_dir: configuration directory.
        :param str cache_dir: directory to cache TRCs and certs in.
        :param str ename: element name, used to generate cache file names.
        :param dict labels:
            Labels added to the exported metrics. The following labels are supported:
                - server_id: A unique identifier of the server that is exporting
                - isd_as: The ISD_AS of where the server is running
        """
        self._dir = os.path.join(conf_dir, CERT_DIR)
        self._cachedir = cache_dir
        self._ename = ename
        self._labels = labels
        self._certs = defaultdict(list)
        self._trcs = defaultdict(list)
        self._trcs_lock = threading.Lock()
        self._certs_lock = threading.Lock()
        self._init_trcs()
        self._init_certs()
        if self._labels:
            self._init_metrics()

    def _init_metrics(self):  # pragma: no cover
        TRCS_TOTAL.labels(**self._labels).set(0)
        CERTS_TOTAL.labels(**self._labels).set(0)

    def _init_trcs(self):  # pragma: no cover
        trcfiles = list(glob.glob("%s/*.trc" % self._dir))
        trcfiles.extend(glob.glob("%s/%s-*.trc" % (self._cachedir, self._ename)))
        for path in trcfiles:
            trc_raw = read_file(path)
            self.add_trc(TRC.from_raw(trc_raw), write=False)
            logging.debug("Loaded: %s" % path)

    def _init_certs(self):  # pragma: no cover
        certfiles = list(glob.glob("%s/*.crt" % self._dir))
        certfiles.extend(glob.glob("%s/%s-*.crt" % (self._cachedir, self._ename)))
        for path in certfiles:
            cert_raw = read_file(path)
            self.add_cert(CertificateChain.from_raw(cert_raw), write=False)
            logging.debug("Loaded: %s" % path)

    def get_trc(self, isd, version=None):
        with self._trcs_lock:
            if not self._trcs[isd]:
                return None
            if version is None or version == 0:
                # Return the most recent TRC.
                _, trc = max(self._trcs[isd])
                return trc
            # Otherwise, try to find a TRC with given version.
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
        with self._certs_lock:
            if not self._certs[isd_as]:
                return None
            if version is None or version == 0:
                # Return the most recent cert.
                _, cert = max(self._certs[isd_as])
                return cert
            # Otherwise, try to find a cert with given version.
            for ver, cert in self._certs[isd_as]:
                if version == ver:
                    return cert
        return None

    def add_trc(self, trc, write=True):
        isd, version = trc.get_isd_ver()
        with self._trcs_lock:
            for ver, _ in self._trcs[isd]:
                if version == ver:
                    return
            self._trcs[isd].append((version, trc))
            if self._labels:
                TRCS_TOTAL.labels(**self._labels).inc()
        if write:
            os.makedirs(self._cachedir, exist_ok=True)
            write_file(os.path.join(self._cachedir,
                                    "%s-ISD%s-V%s.trc" % (self._ename, isd, version)),
                       str(trc))

    def add_cert(self, cert, write=True):
        isd_as, version = cert.get_leaf_isd_as_ver()
        with self._certs_lock:
            for ver, _ in self._certs[isd_as]:
                if version == ver:
                    return
            self._certs[isd_as].append((version, cert))
            if self._labels:
                CERTS_TOTAL.labels(**self._labels).inc()
        if write:
            os.makedirs(self._cachedir, exist_ok=True)
            write_file(
                os.path.join(self._cachedir, "%s-ISD%s-AS%s-V%s.crt" %
                             (self._ename, isd_as.isd_str(), isd_as.as_file_fmt(), version)),
                str(cert))
