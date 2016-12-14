# Copyright 2016 ETH Zurich
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
:mod:`trc` --- SCION TRC parser
===============================================
"""
# Stdlib
import base64
import copy
import json
import logging
import time

# External
import lz4

# SCION
from lib.crypto.asymcrypto import verify
from lib.crypto.certificate import (
    Certificate,
    SIGNATURE_STRING,
    SUBJECT_ENC_KEY_STRING,
    SUBJECT_SIG_KEY_STRING
)
from lib.packet.scion_addr import ISD_AS

ISDID_STRING = 'ISDID'
VERSION_STRING = 'Version'
TIME_STRING = 'Time'
CORE_ASES_STRING = 'CoreCAs'
ROOT_CAS_STRING = 'RootCAs'
LOGS_STRING = 'Logs'
CA_THRESHOLD_STRING = 'CAThreshold'
ROOT_DNS_SERVERS_STRING = 'RootDNSServers'
ROOT_DNS_CERT_STRING = 'RootDNSCert'
QUORUM_OWN_TRC_STRING = 'QuorumOwnTRC'
QUORUM_CAS_STRING = 'QuorumCAs'
QUROUM_DNS_STRING = 'QuorumDNS'
QUARANTINE_STRING = 'Quarantine'
SIGNATURES_STRING = 'Signatures'
GRACE_PERIOD_STRING = 'GracePeriod'


class TRC(object):
    """
    The TRC class parses the TRC file of an ISD and stores such
    information for further use.

    :ivar int isd: the ISD identifier.
    :ivar int version: the TRC file version.
    :ivar int time: the TRC file creation timestamp.
    :ivar dict core_ases: the set of core ASes and their certificates.
    :ivar dict root_cas: the set of root CAs and their certificates.
    :ivar dict logs: is a dictionary of end entity certificate logs, and
        their addresses and public key certificates
    :ivar int ca_threshold: is a threshold number (nonnegative integer) of
        CAs that have to sign a domain’s policy
    :ivar str root_dns_server_addr: the root DNS server's address.
    :ivar str root_dns_server_cert: the root DNS server's certificate.
    :ivar int quorum_own_trc: number of core ASes necessary to sign a new TRC.
    :ivar int quorum_cas: number of CAs necessary to change CA entries
    :ivar int quorum_dns: number of DNS entities necessary to change DNS entries
    :ivar int grace_period: defines for how long this TRC is valid when a new
        TRC is available
    :ivar bool quarantine: flag defining whether TRC is valid(quarantine=false)
        or an early annoncement(quarantine=true)
    :ivar dict signatures: signatures generated by a quorum of trust roots.
    """

    def __init__(self, trc_raw=None, lz4_=False):
        """
        :param str trc_raw: TRC as json string.
        """
        self.isd = 0
        self.version = 0
        self.time = 0
        self.core_ases = {}
        self.root_cas = {}
        self.logs = {}
        self.ca_threshold = 0
        self.root_dns_server_addr = ''
        self.root_dns_server_cert = ''
        self.quorum_own_trc = 0
        self.quorum_cas = 0
        self.quorum_dns = 0
        self.grace_period = 0
        self.quarantine = False
        self.signatures = {}
        if trc_raw:
            self._parse(trc_raw, lz4_)

    def get_isd_ver(self):
        return self.isd, self.version

    def get_core_ases(self):
        res = []
        for key in self.core_ases:
            res.append(ISD_AS(key))
        return res

    def get_trc_dict(self, with_signatures):
        """
        Return the TRC information.

        :param bool with_signatures:
            If True, include signatures in the return value.
        :returns: the TRC information.
        :rtype: dict
        """
        trc_dict = {
            ISDID_STRING: self.isd,
            VERSION_STRING: self.version,
            TIME_STRING: self.time,
            CORE_ASES_STRING: self.core_ases,
            ROOT_CAS_STRING: self.root_cas,
            LOGS_STRING: self.logs,
            CA_THRESHOLD_STRING: self.ca_threshold,
            ROOT_DNS_SERVERS_STRING: self.root_dns_server_addr,
            ROOT_DNS_CERT_STRING: self.root_dns_server_cert,
            QUORUM_OWN_TRC_STRING: self.quorum_own_trc,
            QUORUM_CAS_STRING: self.quorum_cas,
            QUROUM_DNS_STRING: self.quorum_dns,
            GRACE_PERIOD_STRING: self.grace_period,
            QUARANTINE_STRING: self.quarantine}
        if with_signatures:
            trc_dict[SIGNATURES_STRING] = self.signatures
        return trc_dict

    def _parse(self, trc_raw, lz4_):
        """
        Parse a TRC file and populate the instance's attributes.

        :param str trc_raw: TRC as json string.
        """
        if lz4_:
            trc_raw = lz4.loads(trc_raw).decode("utf-8")
        trc = json.loads(trc_raw)
        self.isd = trc[ISDID_STRING]
        self.version = trc[VERSION_STRING]
        self.time = trc[TIME_STRING]
        for subject in trc[CORE_ASES_STRING]:
            cert_dict = base64.b64decode(trc[CORE_ASES_STRING][subject]).\
                decode('utf-8')
            cert_dict = json.loads(cert_dict)
            cert_dict[SUBJECT_SIG_KEY_STRING] = base64.b64decode(
                cert_dict[SUBJECT_SIG_KEY_STRING])
            cert_dict[SUBJECT_ENC_KEY_STRING] = base64.b64decode(
                cert_dict[SUBJECT_ENC_KEY_STRING])
            cert_dict[SIGNATURE_STRING] =\
                base64.b64decode(cert_dict[SIGNATURE_STRING])
            self.core_ases[subject] = Certificate.from_dict(cert_dict)
        self.root_cas = trc[ROOT_CAS_STRING]
        self.logs = trc[LOGS_STRING]
        self.ca_threshold = trc[CA_THRESHOLD_STRING]
        self.root_dns_server_addr = trc[ROOT_DNS_SERVERS_STRING]
        self.root_dns_server_cert = trc[ROOT_DNS_CERT_STRING]
        self.quorum_own_trc = trc[QUORUM_OWN_TRC_STRING]
        self.quorum_cas = trc[QUORUM_CAS_STRING]
        self.quorum_dns = trc[QUROUM_DNS_STRING]
        self.grace_period = trc[GRACE_PERIOD_STRING]
        self.quarantine = trc[QUARANTINE_STRING]
        for subject in trc[SIGNATURES_STRING]:
            self.signatures[subject] = \
                base64.b64decode(trc[SIGNATURES_STRING][subject])

    @classmethod
    def from_values(cls, isd, version, core_ases, root_cas, logs, ca_threshold,
                    root_dns_server_addr, root_dns_server_cert, quorum_own_trc,
                    quorum_cas, quorum_dns, quarantine, signatures,
                    grace_period):
        """
        Generate a TRC instance.
        """
        trc = TRC()
        trc.isd = isd
        trc.version = version
        trc.time = int(time.time())
        trc.core_ases = core_ases
        trc.root_cas = root_cas
        trc.logs = logs
        trc.ca_threshold = ca_threshold
        trc.root_dns_server_addr = root_dns_server_addr
        trc.root_dns_server_cert = root_dns_server_cert
        trc.quorum_own_trc = quorum_own_trc
        trc.quorum_cas = quorum_cas
        trc.quorum_dns = quorum_dns
        trc.grace_period = grace_period
        trc.quarantine = quarantine
        trc.signatures = signatures
        return trc

    def verify(self, oldTRC):
        """
        Perform signature verification for core signatures as defined
        in old TRC.

        :param: oldTRC: the previous TRC which has already been verified.
        :returns: True if verification succeeds, false otherwise.
        :rtype: bool
        """
        # Only look at signatures which are from core ASes as defined in old TRC
        signatures = {k: self.signatures[k] for k in oldTRC.core_ases.keys()}
        # We have more signatures than the number of core ASes in old TRC
        if len(signatures) < len(self.signatures):
            logging.warning("TRC has more signatures than number of core ASes.")
        valid_signature_signers = set()
        # Add every signer to this set whose signature was verified successfully
        for signer in signatures:
            public_key = self.core_ases[signer].subject_sig_key
            if self._verify_signature(signatures[signer], public_key):
                valid_signature_signers.add(signer)
            else:
                logging.warning("TRC contains a signature which could not \
                be verified.")
        # We have fewer valid signatrues for this TRC than quorum_own_trc
        if len(valid_signature_signers) < oldTRC.quorum_own_trc:
            logging.error("TRC does not have the number of required valid \
            signatures")
            return False
        logging.debug("TRC verified.")
        return True

    def _verify_signature(self, signature, public_key):
        """
        Checks if the signature can be verified with the given public key for a
        single signature

        :returns: True if the given signature could be verified with the
            given key, False otherwise
        :rtype bool
        """
        # to_json function sorts the keys
        msg = self.to_json(with_signatures=False).encode('utf-8')
        if not verify(msg, signature, public_key):
            return False
        return True

    def to_json(self, with_signatures=True):
        """
        Convert the instance to json format.
        """
        trc_dict = copy.deepcopy(self.get_trc_dict(with_signatures))
        core_ases = {}
        for subject in trc_dict[CORE_ASES_STRING]:
            cert_str = str(trc_dict[CORE_ASES_STRING][subject])
            core_ases[subject] = base64.b64encode(
                cert_str.encode('utf-8')).decode('utf-8')
        trc_dict[CORE_ASES_STRING] = core_ases
        if with_signatures:
            signatures = {}
            for subject in trc_dict[SIGNATURES_STRING]:
                signature = trc_dict[SIGNATURES_STRING][subject]
                signatures[subject] = base64.b64encode(
                    signature).decode('utf-8')
            trc_dict[SIGNATURES_STRING] = signatures
        trc_str = json.dumps(trc_dict, sort_keys=True, indent=4)
        return trc_str

    def _create_subject_string(self, isd_, as_):
        """
        Helper function to create a subject string out of isdid and asid.
        """
        return str(isd_) + '-' + str(as_)

    def pack(self, lz4_=False):
        ret = self.to_json().encode('utf-8')
        if lz4_:
            return lz4.dumps(ret)
        return ret

    def __str__(self):
        return self.to_json()

    def __eq__(self, other):  # pragma: no cover
        return str(self) == str(other)


def verify_new_TRC(oldTRC, newTRC):
    """
    Check if update from current TRC to updated TRC is valid. Checks if update
    is correct and checks if the new TRC has enough valid signatures as defined
    in the current TRC.

    :returns: True if update is valid, False otherwise
    """
    # Check if update is correct
    if oldTRC.isd != newTRC.isd:
        logging.error("TRC isdid mismatch")
        return False
    if oldTRC.version + 1 != newTRC.version:
        logging.error("TRC versions mismatch")
        return False
    if newTRC.time < oldTRC.time:
        logging.error("New TRC timestamp is not valid")
        return False
    if newTRC.quarantine or oldTRC.quarantine:
        logging.error("Early announcement")
        return False
    # Check if there are enough valid signatures for new TRC
    if not newTRC.verify(oldTRC):
        logging.error("New TRC verification failed, missing or \
        invalid signatures")
        return False
    logging.debug("New TRC verified")
    return True
