#!/usr/bin/env python3

# Copyright 2020 Anapaya Systems

import time

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

        # TODO(scrye): Mangle configuration files of Daemons and Control Services to enable
        # hidden paths.

        print(self._docker_compose("up", "-d"))
        time.sleep(5)

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
