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
import yaml
from http.client import HTTPConnection
from typing import List

from plumbum import local
from plumbum.path.local import LocalPath

from acceptance.common.base import CmdBase, TestBase, TestState, set_name
from acceptance.common.log import LogExec, init_log
from acceptance.common.scion import sciond_addr, SCIONDocker
from acceptance.common.tools import DC
from python.lib.scion_addr import ISD_AS


set_name(__file__)
logger = logging.getLogger(__name__)


class Test(TestBase):
    """
    Test that in a topology with multiple ASes, every AS is capable of
    requesting renewed certificates. The test verifies that each AS has loaded
    the renewed certificate.

    The test is split into multiple steps:
      0. Before starting the topology, remove the client certificate for 112 in the CA CS.
      1. Start the topology.
      2. Restore the client certificate for 112 and wait for it to be picked up by the CA CS.
      3. For each AS in the topology, create a new private key and request
         certificate chain renewal. The renewed chain is verified against the
         TRC.
      4. Remove the previous private key from the control servers.
      5. Ensure that the new private key and certificate are loaded by observing
         the http endpoint.
      6. Check connectivity with an end to end test.
      7. Stop all control servers and purge the state. This includes deleting
         all databases with cached data, including the path and trust database.
      8. Restart control servers and check connectivity again.
    """


@Test.subcommand('setup')
class TestSetup(CmdBase):
    @LogExec(logger, 'setup')
    def main(self):
        # XXX(roosd): In IPv6, the http endpoints are not accessible.
        self.scion.topology('topology/tiny4.topo')

        logger.info('==> Remove client certificate for 112')
        path = local.path('gen/ISD1/ASff00_0_110/cs1-ff00_0_110-1/'
                          'crypto/ca/clients/ISD1-ASff00_0_112.pem')
        path.delete()

        logger.info('==> Start the topology')
        self.scion.run()
        if not self.no_docker:
            self.tools_dc('start', 'tester*')
            self.docker_status()

        logger.info('==> Restore client certificate for 112')
        cert = local.path('gen/certs/ISD1-ASff00_0_112.pem')
        cert.copy(path)

        logger.info('==> Sleep thirty seconds to make sure the CS '
                    'has picked up the client certificate')
        time.sleep(30)


@Test.subcommand('run')
class TestRun(CmdBase):
    @LogExec(logger, 'run')
    def main(self):
        cs_configs = local.path('gen') // 'AS*/cs*.toml'
        isd_ases = []

        logger.info('==> Start renewal process')
        for cs_config in cs_configs:
            isd_as = ISD_AS(cs_config.stem[2:len(cs_config.stem)-2])
            isd_ases.append(isd_as)

            logging.info('===> Start renewal: %s' % isd_as)
            self._renewal_request(cs_config, isd_as)

        logger.info('==> Remove original private keys')
        for cs_config in cs_configs:
            orig_key = cs_config.parent / 'crypto/as/cp-as.key'
            logger.info('Removing original private key for %s: %s' % (isd_as, rel(orig_key)))
            orig_key.delete()

        logger.info('==> Check key and certificate reloads')
        self._check_key_cert(cs_configs)

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

    def _renewal_request(self, cs_config: LocalPath, isd_as: ISD_AS):
        cs_dir = cs_config.parent
        csr = cs_dir / 'crypto/as/csr.json'
        logger.info('Generating CSR for: %s' % rel(csr))
        template = {
            'common_name': '%s InfoSec Squad' % isd_as,
            'country': 'CH',
            'isd_as': str(isd_as),
        }
        with open(csr, 'w') as out:
            json.dump(template, out, indent=4)

        key = cs_dir / 'crypto/as/renewed.key'
        logger.info('Generating new private key: %s' % rel(key))
        local['openssl']('genpkey', '-algorithm', 'EC',
                         '-pkeyopt', 'ec_paramgen_curve:P-256',
                         '-pkeyopt', 'ec_param_enc:named_curve',
                         '-out', cs_dir / 'crypto/as/renewed.key',
                         )

        chain = cs_dir / 'crypto/as/renewed.pem'
        args = [
            '--key', cs_dir / 'crypto/as/renewed.key',
            '--transportkey', cs_dir / 'crypto/as/cp-as.key',
            '--transportcert', cs_dir / ('crypto/as/ISD%s-AS%s.pem' % (
                isd_as.isd_str(), isd_as.as_file_fmt())),
            '--trc', cs_dir / 'certs/ISD1-B1-S1.trc',
            '--out', chain,
            '--sciond', sciond_addr(isd_as),
        ]
        if not self.no_docker:
            chain.touch()
            args += ['--local', self._disp_ip(cs_config.stem)]

        for i in range(len(args)):
            if isinstance(args[i], LocalPath):
                args[i] = str(args[i].relative_to(local.path('.')))

        logger.info('Requesting certificate chain renewal: %s' % rel(chain))
        logger.info(self.scion.execute(isd_as, './bin/scion-pki', 'certs', 'renew', *args))

        logger.info('Verify renewed certificate chain')
        verify_out = local['./bin/scion-pki']('certs', 'verify', chain,
                                              '--trc', 'gen/trcs/ISD1-B1-S1.trc')
        logger.info(str(verify_out).rstrip('\n'))

    def _check_key_cert(self, cs_configs: List[LocalPath]):
        not_ready = []
        for cs_config in cs_configs:
            not_ready.append(cs_config)

        for _ in range(5):
            logger.info('Checking if all control servers have reloaded the key and certificate...')
            for cs_config in not_ready:
                conn = HTTPConnection(self._http_endpoint(cs_config))
                conn.request('GET', '/signer')
                resp = conn.getresponse()
                if resp.status != 200:
                    logger.info("Unexpected response: %d %s", resp.status, resp.reason)
                    continue

                pld = json.loads(resp.read().decode('utf-8'))
                cs_dir = cs_config.parent
                if pld['subject_key_id'] != self._extract_skid(cs_dir / 'crypto/as/renewed.pem'):
                    continue
                logger.info('Control server successfully loaded new key and certificate: %s' %
                            rel(cs_config))
                not_ready.remove(cs_config)
            if not not_ready:
                break
            time.sleep(3)
        else:
            logger.error('Control servers without reloaded key and certificate: %s' %
                         [cs_config.name for cs_config in not_ready])
            sys.exit(1)

    def _http_endpoint(self, cs_config: LocalPath):
        with open(cs_config, 'r') as f:
            cfg = toml.load(f)
            return cfg['metrics']['prometheus']

    def _extract_skid(self, file: LocalPath):
        cert = local['openssl']['x509', '-in', file, '-noout', '-text']
        grep = local['grep']['-A1', 'Subject Key Identifier']
        search = cert | grep
        return search().split()[-1].replace(':', ' ').upper()

    def _disp_ip(self, cs_name: str):
        with open('gen/scion-dc.yml') as f:
            dc = yaml.load(f, Loader=yaml.FullLoader)
            networks = dc['services']['scion_disp_%s' % cs_name]['networks']
            for _, network in networks.items():
                if 'ipv6_address' in network:
                    return network['ipv6_address']
                return network['ipv4_address']


def rel(path: LocalPath):
    return path.relative_to(local.path('.'))


if __name__ == '__main__':
    init_log()
    Test.test_state = TestState(SCIONDocker(), DC())
    Test.run()
