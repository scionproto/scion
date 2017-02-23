#!/usr/bin/python3
# Copyright 2014 ETH Zurich
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
:mod:`base` --- SCION certificate server
========================================
"""
# Stdlib
import logging
import threading

# External packages
from Crypto.Hash import SHA256

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.defines import CERTIFICATE_SERVICE
from lib.main import main_default, main_wrapper
from lib.packet.cert_mgmt import (
    CertChainReply,
    TRCReply,
)
from lib.packet.scion import msg_from_raw
from lib.requests import RequestHandler
from lib.thread import thread_safety_net
from lib.types import CertMgmtType, PayloadClass
from lib.util import (
    SCIONTime,
    sleep_interval,
)
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import Zookeeper


class CertServer(SCIONElement):
    """
    The SCION Certificate Server.
    """
    SERVICE_TYPE = CERTIFICATE_SERVICE
    # ZK path for incoming cert chains
    ZK_CC_CACHE_PATH = "cert_chain_cache"
    # ZK path for incoming TRCs
    ZK_TRC_CACHE_PATH = "trc_cache"

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        
        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
            },
        }

        zkid = ZkID.from_values(self.addr.isd_as, self.id,
                                [(self.addr.host, self._port)]).pack()
        self.zk = Zookeeper(self.topology.isd_as, CERTIFICATE_SERVICE,
                            zkid, self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)
        self.trc_cache = ZkSharedCache(self.zk, self.ZK_TRC_CACHE_PATH,
                                       self._cached_entries_handler)
        self.cc_cache = ZkSharedCache(self.zk, self.ZK_CC_CACHE_PATH,
                                      self._cached_entries_handler)

    def worker(self):
        """
        Worker thread that takes care of reading shared entries from ZK, and
        handling master election.
        """
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "CS.worker cycle",
                           self._quiet_startup())
            start = SCIONTime.get_time()
            try:
                self.zk.wait_connected()
                self.trc_cache.process()
                self.cc_cache.process()
                # Try to become a master.
                if self.zk.get_lock(lock_timeout=0, conn_timeout=0):
                    self.trc_cache.expire(worker_cycle * 10)
                    self.cc_cache.expire(worker_cycle * 10)
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass

    def _cached_entries_handler(self, raw_entries):
        """
        Handles cached (through ZK) TRCs and Cert Chains.
        """
        for entry in raw_entries:
            payload = msg_from_raw(entry)
            if isinstance(payload, CertChainReply):
                self.process_cert_chain_reply(payload, None, from_zk=True)
            elif isinstance(payload, TRCReply):
                self.process_trc_reply(payload, None, from_zk=True)
            else:
                logging.warning("Entry with unsupported type: %s" % entry)

    def _share_object(self, pld, is_trc):
        """
        Share path segments (via ZK) with other path servers.
        """
        pld_packed = pld.pack()
        pld_hash = SHA256.new(pld_packed).hexdigest()
        try:
            if is_trc:
                self.trc_cache.store("%s-%s" % (pld_hash, SCIONTime.get_time()),
                                     pld_packed)
            else:
                self.cc_cache.store("%s-%s" % (pld_hash, SCIONTime.get_time()),
                                    pld_packed)
        except ZkNoConnection:
            logging.warning("Unable to store %s in shared path: "
                            "no connection to ZK" % "TRC" if is_trc else "CC")
            return
        logging.debug("%s stored in ZK: %s" % ("TRC" if is_trc else "CC",
                                               pld_hash))

    def run(self):
        """
        Run an instance of the Cert Server.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="CS.worker", daemon=True).start()
        super().run()


if __name__ == "__main__":
    main_wrapper(main_default, CertServer)
