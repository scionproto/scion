"""
rot_parser.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from collections import defaultdict
import logging

from lib.packet.host_addr import *
import xml.etree.ElementTree as ET


class Element(object):
    """
    Base class for elements specified in the topology file.
    """
    def __init__(self, ad_id=0, len=0):
        self.ad_id = ad_id
        self.len = len


class CoreADElement(Element):
    """
    Represents the certificate of one of the core ADs in SCION.
    """
    def __init__(self, ad_id=0, len=0, cert=None):
        Element.__init__(self, ad_id, len)
        self.cert = cert


class SignatureElement(Element):
    """
    Represents a certificate signature.
    """
    def __init__(self, ad_id=0, len=0, sign=None):
        Element.__init__(self, ad_id, len)
        self.sign = sign


class Rot(object):
    """
    Handles parsing a SCION Root of Trust XML file.
    """
    def __init__(self, filename=None):
        self.version = 0
        self.issue_date = None
        self.expire_date = None
        self.isd_id = 0
        self.policy_threshold = 0
        self.certificate_threshold = 0
        self.core_ads = {}
        self.signatures = {}
        self._filename = None
        self._rot = None
        if filename is not None:
            self.load_file(filename)

    def load_file(self, filename):
        """
        Loads an XML file and creates an element tree for further parsing.
        """
        assert isinstance(filename, str)
        self._filename = filename
        self._rot = ET.parse(filename)

    def parse(self):
        """
        Parses the rot file and populates
        """
        assert self._rot is not None, "Must load file first"
        header = self._rot.getroot().find("header")
        assert header is not None, "Header part missing"
        version = header.find("version")
        if version is not None:
            self.version = int(version.text)
        issue_date = header.find("issueDate")
        if issue_date is not None:
            self.issue_date = issue_date.text
        expire_date = header.find("expireDate")
        if expire_date is not None:
            self.expire_date = expire_date.text
        isd_id = header.find("ISDID")
        if isd_id is not None:
            self.isd_id = int(isd_id.text)
        policy_threshold = header.find("policyThreshold")
        if policy_threshold is not None:
            self.policy_threshold = int(policy_threshold.text)
        certificate_threshold = header.find("certificateThreshold")
        if certificate_threshold is not None:
            self.certificate_threshold = int(certificate_threshold.text)
        self._parse_core_ads()
        self._parse_signatures()

    def _parse_core_ads(self):
        """
        Parses the core ADs in the rot file.
        """
        core_ads = self._rot.getroot().find("coreADs")
        if core_ads is None:
            logging.info("No core ADs found in %s", self._filename)
            return
        for core_ad in core_ads:
            assert ET.iselement(core_ad)
            ad_id = int(core_ad.find("ADID").text)
            len = int(core_ad.find("len").text)
            cert = core_ad.find("cert").text
            element = CoreADElement(ad_id, len, cert)
            self.core_ads[ad_id] = element

    def _parse_signatures(self):
        """
        Parses the signatures in the rot file.
        """
        signatures = self._rot.getroot().find("signatures")
        if signatures is None:
            logging.info("No signatures found in %s", self._filename)
            return
        for signature in signatures:
            assert ET.iselement(signature)
            ad_id = int(signature.find("ADID").text)
            len = int(signature.find("len").text)
            sign = signature.find("sign").text
            element = SignatureElement(ad_id, len, sign)
            self.signatures[ad_id] = element       


# For testing purposes
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: %s <rotfile>" % sys.argv[0])
        sys.exit()
    parser = Rot(sys.argv[1])
    parser.parse()
