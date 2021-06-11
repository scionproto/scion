#!/usr/bin/env python3

# Copyright 2021 Anapaya Systems
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

import json
import logging
import pathlib
import subprocess
import time
from typing import List
import sys
from http import client

from plumbum import cli

from acceptance.common import base
from acceptance.common import docker
from acceptance.common import log
from acceptance.common import scion
from python.lib import scion_addr
import toml

logger = logging.getLogger(__name__)


class Test(base.TestBase):
    """
    Test that in a topology with multiple ASes, every AS is capable of
    requesting renewed certificates. The test verifies that each AS has loaded
    the renewed certificate.

    The test is split into multiple steps:
      1. Start the topology.
      2. For each AS in the topology, create a new private key and request
         certificate chain renewal. The renewed chain is verified against the
         TRC.
      3. Remove the previous private key from the control servers.
      4. Ensure that the new private key and certificate are loaded by observing
         the http endpoint.
      5. Check connectivity with an end to end test.
      6. Stop all control servers and purge the state. This includes deleting
         all databases with cached data, including the path and trust database.
      7. Restart control servers and check connectivity again.
    """
    end2end = cli.SwitchAttr(
        "end2end_integration",
        str,
        default="./bin/end2end_integration",
        help="The end2end_integration binary " +
        "(default: ./bin/end2end_integration)",
    )

    def main(self):
        if not self.nested_command:
            try:
                self.setup()
                # Give some time for the topology to start.
                time.sleep(10)
                self._run()
            finally:
                self.teardown()

    def _run(self):
        isd_ases = scion.ASList.load("%s/gen/as_list.yml" %
                                     self.test_state.artifacts).all
        cs_configs = self._cs_configs()

        logger.info("==> Start renewal process")
        for isd_as in isd_ases:
            logging.info("===> Start renewal: %s" % isd_as)
            self._renewal_request(isd_as)

        logger.info("==> Check key and certificate reloads")
        self._check_key_cert(cs_configs)

        logger.info("==> Check connectivity")
        subprocess.run(
            [self.end2end, "-d", "-outDir", self.test_state.artifacts],
            check=True)

        logger.info("==> Shutting down control servers and purging caches")
        for container in self.list_containers("scion_sd.*"):
            self.test_state.dc("rm", container)
        for container in self.list_containers("scion_cs.*"):
            self.stop_container(container)
        for cs_config in cs_configs:
            files = list((pathlib.Path(self.test_state.artifacts) /
                          "gen-cache").glob("%s*" % cs_config.stem))
            for db_file in files:
                db_file.unlink()
            logger.info("Deleted files: %s" % [file.name for file in files])

        logger.info("==> Restart containers")
        self.setup_start()
        time.sleep(5)

        logger.info("==> Check connectivity")
        subprocess.run(
            [self.end2end, "-d", "-outDir", self.test_state.artifacts],
            check=True)

        logger.info("==> Backup mode")
        for isd_as in isd_ases:
            logging.info("===> Start renewal: %s" % isd_as)
            self._renewal_request(isd_as, mode="--backup")

    def _renewal_request(
        self,
        isd_as: scion_addr.ISD_AS,
        mode: str = "--force",
    ):
        as_dir = self._to_as_dir(isd_as)
        docker_dir = pathlib.Path("/share") / self._rel(as_dir)

        def read_file(filename: str) -> str:
            with open(as_dir / "crypto/as" / filename) as f:
                return f.read()

        chain_name = "ISD%s-AS%s.pem" % (isd_as.isd_str(),
                                         isd_as.as_file_fmt())
        old_chain = read_file(chain_name)
        old_key = read_file("cp-as.key")

        chain = docker_dir / "crypto/as" / chain_name
        args = [
            chain,
            docker_dir / "crypto/as/cp-as.key",
            mode,
            "--trc",
            docker_dir / "certs/ISD1-B1-S1.trc",
            "--sciond",
            self.execute("tester_%s" % isd_as.file_fmt(), "sh", "-c",
                         "echo $SCION_DAEMON").strip(),
            *self._local_flags(isd_as),
        ]

        logger.info("Requesting certificate chain renewal: %s" %
                    chain.relative_to(docker_dir))
        logger.info(
            self.execute("tester_%s" % isd_as.file_fmt(), "./bin/scion-pki",
                         "certificate", "renew", *args))

        logger.info("Verify renewed certificate chain")
        verify_out = self.execute("tester_%s" % isd_as.file_fmt(),
                                  "./bin/scion-pki", "certificate", "verify",
                                  chain, "--trc",
                                  "/share/gen/trcs/ISD1-B1-S1.trc")
        logger.info(str(verify_out).rstrip("\n"))

        renewed_chain = read_file(chain_name)
        renewed_key = read_file("cp-as.key")
        if renewed_chain == old_chain:
            raise Exception(
                "renewed chain does not differ from previous chain")
        if renewed_key == old_key:
            raise Exception("renewed key does not differ from previous key")

    def _check_key_cert(self, cs_configs: List[pathlib.Path]):
        not_ready = [*cs_configs]

        for _ in range(5):
            logger.info(
                "Checking if all control servers have reloaded the key and certificate..."
            )
            for cs_config in not_ready:
                conn = client.HTTPConnection(self._http_endpoint(cs_config))
                conn.request("GET", "/signer")
                resp = conn.getresponse()
                if resp.status != 200:
                    logger.info("Unexpected response: %d %s", resp.status,
                                resp.reason)
                    continue

                isd_as = scion_addr.ISD_AS(cs_config.stem[2:-2])
                as_dir = self._to_as_dir(isd_as)
                chain_name = "ISD%s-AS%s.pem" % (isd_as.isd_str(),
                                                 isd_as.as_file_fmt())

                pld = json.loads(resp.read().decode("utf-8"))
                if pld["subject_key_id"] != self._extract_skid(
                        as_dir / "crypto/as" / chain_name):
                    continue
                logger.info(
                    "Control server successfully loaded new key and certificate: %s"
                    % self._rel(cs_config))
                not_ready.remove(cs_config)
            if not not_ready:
                break
            time.sleep(3)
        else:
            logger.error(
                "Control servers without reloaded key and certificate: %s" %
                [cs_config.name for cs_config in not_ready])
            sys.exit(1)

    def _http_endpoint(self, cs_config: pathlib.Path):
        with open(cs_config, "r") as f:
            cfg = toml.load(f)
            return cfg["metrics"]["prometheus"]

    def _extract_skid(self, file: pathlib.Path):
        out = subprocess.check_output(
            ['openssl', 'x509', '-in', file, '-noout', '-text'])
        lines = out.splitlines()
        for i, v in enumerate(lines):
            if v.decode("utf-8").find("Subject Key Identifier") > -1:
                skid = lines[i + 1].decode("utf-8").split()[-1].replace(
                    ":", " ").upper()
                break
        return skid

    def _rel(self, path: pathlib.Path):
        return path.relative_to(pathlib.Path(self.test_state.artifacts))

    def _to_as_dir(self, isd_as: scion_addr.ISD_AS) -> pathlib.Path:
        return pathlib.Path("%s/gen/AS%s" %
                            (self.test_state.artifacts, isd_as.as_file_fmt()))

    def _cs_configs(self) -> List[pathlib.Path]:
        return list(
            pathlib.Path("%s/gen" %
                         self.test_state.artifacts).glob("AS*/cs*.toml"))

    def _local_flags(self, isd_as: scion_addr.ISD_AS) -> List[str]:
        return [
            "--local",
            self.execute("tester_%s" % isd_as.file_fmt(), "sh", "-c",
                         "echo $SCION_LOCAL_ADDR").strip(),
        ]


if __name__ == "__main__":
    log.init_log()
    base.register_commands(Test)
    base.TestBase.test_state = base.TestState(scion.SCIONDocker(),
                                              docker.Compose())
    Test.run()
