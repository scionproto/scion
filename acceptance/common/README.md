## Acceptance Testing

This module provides a simple acceptance testing library.

### Structure

An acceptance test is structured fairly simple. It exposes a way
to implement the necessary sub-commands for `acceptance/run`.
At the core is the `Base` class. It implements the `name` and `teardown`
sub-commands. The `setup` and `run` command must be implemented by
each test individually.

`Base` registers two flags that also can be set using environment variables:
- `--artifacts/ACCEPTANCE_ARTIFACTS` defines the directory for artifacts
  (required)
- `--disable-docker/DISABLE_DOCKER` disables the dockerized topology.
  This allows for faster development cycle.

Additionally, the base stores utility classes that help
interacting with the infrastructure in fields:
- `scion` can be used to start and stop the scion infrastructure,
   or interact with individual service processes.
- `dc` can be used to interact with docker compose.

### Writing Your Own Test

Write your own test by adding a directory to `acceptance` with the suffix
`_acceptance`. This suffix is required by the acceptance framework.

Add your test file as `new_test_acceptance/test` (without `.py`) and
make it executable with `chmod +x`.

A minimal working test can be written as follows:

````python
#!/usr/bin/env python3

import logging

from plumbum import local

from acceptance.common.log import LogExec, init_log
from acceptance.common.base import Base, set_name

# Set the name of the test. It is inferred from the file path.
set_name(__file__)
# Get logger. (Optional)
logger = logging.getLogger(__name__)


class Test(Base):
    """
    Fill in the test description here. Plumbum will use it as output
    in if the --help flag is set, or the provided flags are invalid.
    """


# This decorator defines the sub-command setup.
@Test.subcommand('setup')
class TestSetup(Test):
    # This decorator logs start and end of the call.
    @LogExec(logger, 'setup')
    def main(self):
        # Create test dir if it does not exist.
        self.cmd_setup()
        # Create the tiny topology/
        self.scion.topology('topology/Tiny.topo')
        # Modify the logging config for all beacon servers
        self.scion.set_configs({'logging.file.Level': 'trace'},
                               local.path('gen/ISD1') // '*/bs*/bs.toml')
        # Run the scion topology.
        self.scion.run()
        # Start the tester container in the dockerized topology.
        if not self.no_docker:
            self.tools_dc('start', 'tester*')
            self.docker_status()


# This decorator defines the sub-command run.
@Test.subcommand('run')
class TestRun(Test):
    # This decorator logs start and end of the call.
    @LogExec(logger, 'run')
    def main(self):
        # Run end-to-end test.
        self.scion.run_end2end()


if __name__ == '__main__':
    init_log()
    Test.run()
````
