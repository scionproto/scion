#!/usr/bin/env python3

# Copyright 2020 Anapaya Systems

import http.server
import time
import threading

from plumbum import cmd

from acceptance.common import base
from acceptance.common import log
from acceptance.common import tools
from acceptance.common import scion


class Test(base.TestBase):
    """
    Constructs a simple Hidden Paths topology with one core, four leaf ASes and
    two hidden path groups.

    AS 1-ff00:0:1 is core.
    AS 1-ff00:0:2, 1-ff00:0:3, 1-ff00:0:4, 1-ff00:0:5 are leaves.

    We use the shortnames AS1, AS2, etc. for the ASes above.

    The two hidden paths groups are owned by the registry AS, and indexed
    according to who the writer AS is. The groups are as follows:

      Group ff00:0:2-3 contains the following roles:
        Registry: AS2
        Writer:   AS3
        Client:   AS5

      Group ff00:0:2-4 contains the following roles
        Registry: AS2
        Writer:   AS4
        Client:   AS5

    We test for connectivity between all pairs of ASes in the same group.
    Testing is done using showpaths with JSON output.
    Additionally, we test that the ASes in different groups cannot talk
    to each other. Thus, the tests are:
      Expect connectivity:
        AS2 <-> AS3, AS2 <-> AS5, AS3 <-> AS5 (Group ff00:0:2-3)
        AS2 <-> AS4, AS2 <-> AS5, AS4 <-> AS5 (Group ff00:0:2-4)
      Expect no connectivity:
        AS3 <-> AS4 (Group ff00:0:2-3 to group ff00:0:2-4)
    """

    def main(self):
        print("artifacts dir: %s" % self.test_state.artifacts)
        self._unpack_topo()
        if not self.nested_command:
            try:
                self._setup()
                time.sleep(20)
                self._run()
            finally:
                self._teardown()

    def _unpack_topo(self):
        cmd.tar("-xf", "./acceptance/hidden_paths/gen.tar",
                "-C", self.test_state.artifacts)
        cmd.sed("-i", "s#$SCIONROOT#%s#g" % self.test_state.artifacts,
                self.test_state.artifacts / "gen/scion-dc.yml")

    def _docker_compose(self, *args) -> str:
        return cmd.docker_compose("-f", self.test_state.artifacts / "gen" / "scion-dc.yml",
                                  "-p", "scion", *args)

    def _setup(self):
        print(cmd.docker("image", "load", "-i",
              "./acceptance/hidden_paths/testcontainers.tar"))

        http_server_port = 9090

        as_numbers = ["2", "3", "4", "5"]
        # HTTP configuration server runs on 0.0.0.0 and needs to be reachable from
        # every daemon and control service. There is one host IP on every AS bridge.
        # We use this IP for the configuration download URLs.
        server_ips = {
            "2": "172.20.0.49",
            "3": "172.20.0.57",
            "4": "172.20.0.65",
            "5": "172.20.0.73",
        }
        control_addresses = {
            "2": "172.20.0.51:30252",
            "3": "172.20.0.59:30252",
            "4": "172.20.0.67:30252",
            "5": "172.20.0.75:30252",
        }
        # Each AS participating in hidden paths has their own hidden paths configuration file.
        hp_configs = {
            "2": "hp_groups_as2_as5.yml",
            "3": "hp_groups_as3.yml",
            "4": "hp_groups_as4.yml",
            "5": "hp_groups_as2_as5.yml",
        }

        # Edit all the configuration files of daemons and control services with
        # the computed configuration URL
        for as_number in as_numbers:
            hp_config_url = "http://%s:%d/acceptance/hidden_paths/testdata/%s" % (
                server_ips[as_number], http_server_port, hp_configs[as_number])

            as_dir = "ASff00_0_%s" % as_number
            as_dir_path = self.test_state.artifacts / "gen" / as_dir

            daemon_path = as_dir_path / "sd.toml"
            scion.update_toml({"sd.hidden_path_groups": hp_config_url}, [daemon_path])

            control_id = "cs1-ff00_0_%s-1" % as_number
            control_file = "%s.toml" % control_id
            control_path = as_dir_path / control_file
            scion.update_toml({"path.hidden_paths_cfg": hp_config_url}, [control_path])

            # For simplicity, expose the services in all hidden paths ASes,
            # even though some don't need the registration service.
            topology_update = {
                "hidden_segment_lookup_service.%s.addr" % control_id:
                    control_addresses[as_number],
                "hidden_segment_registration_service.%s.addr" % control_id:
                    control_addresses[as_number],
            }
            topology_file = as_dir_path / "topology.json"
            scion.update_json(topology_update, [topology_file])

        server = http.server.HTTPServer(("0.0.0.0", 9090), http.server.SimpleHTTPRequestHandler)
        server_thread = threading.Thread(target=configuration_server, args=[server])
        server_thread.start()

        print(self._docker_compose("up", "-d"))
        time.sleep(10)  # Give applications time to download configurations

        self._testers = {
            "2": "tester_1-ff00_0_2",
            "3": "tester_1-ff00_0_3",
            "4": "tester_1-ff00_0_4",
            "5": "tester_1-ff00_0_5",
        }
        self._ases = {
            "2": "1-ff00:0:2",
            "3": "1-ff00:0:3",
            "4": "1-ff00:0:4",
            "5": "1-ff00:0:5",
        }
        self._daemons_api = {
            "2": "172.20.0.52:30255",
            "3": "172.20.0.60:30255",
            "4": "172.20.0.68:30255",
            "5": "172.20.0.76:30255",
        }
        server.shutdown()

    def _run(self):
        # Group 3
        self._showpaths_bidirectional("2", "3", 0)
        self._showpaths_bidirectional("2", "5", 0)
        self._showpaths_bidirectional("3", "5", 0)

        # Group 4
        self._showpaths_bidirectional("2", "4", 0)
        self._showpaths_bidirectional("2", "5", 0)
        self._showpaths_bidirectional("4", "5", 0)

        # Group 3 X 4
        # FIXME(scrye): When hidden paths is implemented, the below should fail.
        # Change to 1.
        self._showpaths_bidirectional("3", "4", 0)

    def _showpaths_bidirectional(self, source: str, destination: str, retcode: int):
        self._showpaths_run(source, destination, retcode)
        self._showpaths_run(destination, source, retcode)

    def _showpaths_run(self, source_as: str, destination_as: str, retcode: int):
        print(cmd.docker("exec", "-t", self._testers[source_as], "./bin/scion",
                         "sp", self._ases[destination_as],
                         "--sciond", self._daemons_api[source_as],
                         "--timeout", "2s",
                         "--no-probe",  # FIXME(scrye): Testers always time out, but paths exist.
                         retcode=retcode))

    def _teardown(self):
        logs = self._docker_compose("logs")
        with open(self.test_state.artifacts / "logs" / "docker-compose.log", "w") as f:
            f.write(logs)
        print(self._docker_compose("down", "-v"))


@Test.subcommand("setup")
class TestSetup(Test):

    def main(self):
        self._setup()


@Test.subcommand("teardown")
class TestTeardown(Test):

    def main(self):
        self._teardown()


if __name__ == "__main__":
    log.init_log()
    Test.test_state = base.TestState(scion.SCIONDocker(), tools.DC())
    Test.run()


def configuration_server(server):
    print("HTTP configuration server starting on %s:%d." % server.server_address)
    server.serve_forever()
    print("HTTP configuration server closed.")
