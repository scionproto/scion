#!/usr/bin/env python3

# Copyright 2020 Anapaya Systems
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

import logging
import json
import time
import toml
import sys
from http.client import HTTPConnection
from typing import List

from plumbum import local
from plumbum.path.local import LocalPath

from acceptance.common import base

logger = logging.getLogger(__name__)


class Test(base.TestTopogen):
    """
    Test that in a topology with multiple ASes, every AS notices TRC updates
    through the beaconing process. The test verifies that each AS receives
    the updated TRC, and uses it for signing control plane messages.

    The test is split into multiple steps:
      1. Start the topology.
      2. Create a TRC update and push it to the authoritative core AS.
      3. Ensure that the new TRC is used by observing the http endpoint.
      4. Check connectivity with an end to end test.
      5. Stop all control servers and purge the state. This includes deleting
         all databases with cached data, including the path and trust database.
      6. Restart control servers and check connectivity again.
    """

    def _run(self):
        # Give some time for the topology to start.
        time.sleep(10)

        artifacts = self.artifacts
        cs_configs = artifacts // 'gen/AS*/cs*.toml'

        logger.info('==> Generate TRC update')
        scion_pki = self.get_executable("scion-pki")
        scion_pki['testcrypto', 'update', '-o', artifacts / 'gen'].run_fg()

        target = 'gen/ASff00_0_110/crypto/as'
        logger.info('==> Copy to %s' % target)
        local['cp'](artifacts / 'gen/trcs/ISD1-B1-S2.trc', artifacts / target)

        logger.info('==> Wait for authoritative core to pick up the TRC update')
        time.sleep(10)

        logger.info('==> Check TRC update received')
        self._check_update_received(cs_configs)

        logger.info("==> Check connectivity")
        end2end = self.get_executable("end2end_integration")
        end2end["-d", "-outDir", artifacts].run_fg()

        logger.info('==> Shutting down control servers and purging caches')
        cs_services = self.dc.list_containers(".*_cs.*")
        for cs in cs_services:
            self.dc.stop_container(cs)

        for cs_config in cs_configs:
            files = artifacts // ('gen-cache/%s*' % cs_config.stem)
            for db_file in files:
                db_file.delete()
            logger.info('Deleted files: %s' % [file.name for file in files])

        for cs in cs_services:
            self.dc.start_container(cs)
        time.sleep(5)

        logger.info('==> Check connectivity')
        end2end("-d", "-outDir", artifacts)

    def _check_update_received(self, cs_configs: List[LocalPath]):
        not_ready = []
        for cs_config in cs_configs:
            not_ready.append(cs_config)

        for _ in range(5):
            logger.info('Checking if all control servers have received the TRC update...')
            for cs_config in not_ready:
                conn = HTTPConnection(self._http_endpoint(cs_config))
                conn.request('GET', '/signer')
                resp = conn.getresponse()
                if resp.status != 200:
                    logger.info("Unexpected response: %d %s", resp.status, resp.reason)
                    continue

                pld = json.loads(resp.read().decode('utf-8'))
                if pld['trc_id']['serial_number'] != 2:
                    continue
                logger.info('Control server received TRC update: %s' % self._rel(cs_config))
                not_ready.remove(cs_config)
            if not not_ready:
                break
            time.sleep(3)
        else:
            logger.error('Control servers that have not received TRC update: %s' %
                         [cs_config.stem for cs_config in not_ready])
            sys.exit(1)

    def _http_endpoint(self, cs_config: LocalPath):
        with open(cs_config, 'r') as f:
            cfg = toml.load(f)
            return cfg['metrics']['prometheus']

    def _rel(self, path):
        return path.relative_to(self.artifacts)


if __name__ == '__main__':
    base.main(Test)
