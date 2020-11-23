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

from acceptance.common.base import CmdBase, TestBase, TestState, set_name
from acceptance.common.log import LogExec, init_log
from acceptance.common.scion import SCIONDocker
from acceptance.common.tools import DC


set_name(__file__)
logger = logging.getLogger(__name__)


class Test(TestBase):
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


@Test.subcommand('setup')
class TestSetup(CmdBase):
    @LogExec(logger, 'setup')
    def main(self):
        # XXX(roosd): In IPv6, the http endpoints are not accessible.
        self.scion.topology('topology/tiny4.topo')
        self.scion.run()
        if not self.no_docker:
            self.tools_dc('start', 'tester*')
            self.docker_status()


@Test.subcommand('run')
class TestRun(CmdBase):
    @LogExec(logger, 'run')
    def main(self):
        cs_configs = local.path('gen') // 'AS*/cs*.toml'

        logger.info('==> Generate TRC update')
        local['./bin/scion-pki']('testcrypto', 'update', '-o', 'gen')

        target = 'gen/ASff00_0_110/crypto/as'
        logger.info('==> Copy to %s' % target)
        local['cp']('gen/trcs/ISD1-B1-S2.trc', target)

        logger.info('==> Wait for authoritative core to pick up the TRC update')
        time.sleep(10)

        logger.info('==> Check TRC update received')
        self._check_update_received(cs_configs)

        logger.info("==> Check connectivity")
        self.scion.run_end2end()

        logger.info('==> Shutting down control servers and purging caches')
        for cs_config in cs_configs:
            files = local.path('gen-cache') // ('%s*' % cs_config.stem)
            for db_file in files:
                db_file.delete()
            logger.info('Deleted files: %s' % [file.name for file in files])

        self.scion.run()
        time.sleep(5)

        logger.info('==> Check connectivity')
        self.scion.run_end2end()

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
                logger.info('Control server received TRC update: %s' % rel(cs_config))
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


def rel(path: LocalPath):
    return path.relative_to(local.path('.'))


if __name__ == '__main__':
    init_log()
    Test.test_state = TestState(SCIONDocker(), DC())
    Test.run()
