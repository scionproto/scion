# Acceptance Testing

This module provides a simple acceptance testing library.

## Structure

An acceptance test is structured fairly simple. It exposes a way
to implement the necessary sub-commands for `acceptance/run`.
At the core are the `TestBase` and `CmdBase` classes. A test should
have multiple classes. One class `Test` that sub-classes `common.TestBase`,
with only a doc string. This doc comment used in the output when running the
command with `--help` flag. Furthermore, a test should have one class per
sub-command that sub-classes `common.CmdBase` (see below).

`TestBase` registers two flags that also can be set using environment variables:

- `--artifacts/ACCEPTANCE_ARTIFACTS` defines the directory for artifacts
  (required)

The sub-commands should sub-class `common.CmdBase`. `CmdBase` has defined some
common properties and methods that are useful for test writing and interacting
with the infrastructure, such as:

- `scion` can be used to start and stop the scion infrastructure,
   or interact with individual service processes.
- `dc` can be used to interact with docker compose.

Sub-commands are registered with the `@Test.subcommand` decorator.
By default, the `name` and `teardown` sub-command are already implemented.
The `setup` and `run` command must be implemented by each test individually.

## Writing Your Own Test

Write your own test by adding a directory to `acceptance` with the suffix
`_acceptance`. This suffix is required by the acceptance framework.

Add your test file as `new_test_acceptance/test` (without `.py`) and
make it executable with `chmod +x`.

A minimal working test can be written as follows:

```python
#!/usr/bin/env python3

import logging

from plumbum import local

from acceptance.common.log import LogExec, init_log
from acceptance.common.base import CmdBase, TestBase, set_name

# Set the name of the test. It is inferred from the file path.
set_name(__file__)
# Get logger. (Optional)
logger = logging.getLogger(__name__)


class Test(TestBase):
    """
    Fill in the test description here. Plumbum will use it as output
    in if the --help flag is set, or the provided flags are invalid.
    """


# This decorator defines the sub-command setup.
@Test.subcommand("setup")
class TestSetup(CmdBase):
    """ This doc string is used in the sub-command help. """

    # This decorator logs start and end of the call.
    @LogExec(logger, "setup")
    def main(self):
        # Create test dir if it does not exist.
        self.cmd_setup()
        # Create the tiny topology/
        self.scion.topology("topology/tiny.topo")
        # Modify the logging config for all beacon servers
        scion.update_toml({"log.file.level": "debug"}, local.path("gen/) // "*/bs*.toml")
        # Run the scion topology.
        self.scion.run()
        # Start the tester container in the dockerized topology.
        if not self.no_docker:
            self.tools_dc("start", "tester*")
            self.docker_status()


# This decorator defines the sub-command run.
@Test.subcommand("run")
class TestRun(CmdBase):
    """ This doc string is used in the sub-command help. """

    # This decorator logs start and end of the call.
    @LogExec(logger, "run")
    def main(self):
        # Run end-to-end test.
        self.scion.run_end2end()


if __name__ == "__main__":
    init_log()
    Test.run()
```
