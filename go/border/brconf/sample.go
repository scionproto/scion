// Copyright 2018 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package brconf

const Sample = `[general]
  # The ID of the service. This is used to choose the relevant portion of the
  # topology file for some services.
  ID = "br-1"

  # Directory for loading AS information, certs, keys, path policy, topology.
  ConfigDir = "/etc/scion"

  # Topology file. If not specified, topology.json is loaded from the config
  # directory.
  # Topology = "/etc/scion/topology.json"

[logging]
  [logging.file]
    # Location of the logging file.
    Path = "/var/log/scion/br-1.log"

    # File logging level (trace|debug|info|warn|error|crit) (default debug)
    Level = "debug"

    # Max size of log file in MiB (default 50)
    # Size = 50

    # Max age of log file in days (default 7)
    # MaxAge = 7

    # MaxBackups is the maximum number of log files to retain (default 10)
    # MaxBackups = 10

    # How frequently to flush to the log file, in seconds. If 0, all messages
    # are immediately flushed. If negative, messages are never flushed
    # automatically. (default 5)
    FlushInterval = 5
  [logging.console]
    # Console logging level (trace|debug|info|warn|error|crit) (default crit)
	Level = "crit"

[metrics]
  # The address to export prometheus metrics on. If not set, metrics are not
  # exported.
  # Prometheus = "127.0.0.1:8000"

[discovery]
  # Allow changes to the semi-mutable section during updates to the static
  # topology fetched from the discovery service. (default false)
  AllowSemiMutable = false

  [discovery.static]
    # Enable periodic fetching of the static topology. (default false)
    Enable = false

    # Time between two consecutive static topology queries. (default 5m)
    Interval = "5m"

    # Timeout for querying the static topology. (default 1s)
    Timeout = "1s"

    # Require https connection. (default false)
    Https = false

    # Filename where the updated static topologies are written. In case of the
    # empty string, the updated topologies are not written. (default "")
    Filename = ""

    [discovery.static.connect]
      # Maximum time spent attempting to fetch the topology from the
      # discovery service on start. If no topology is successfully fetched
      # in this period, the FailAction is executed. (default 20s)
      InitialPeriod = "20s"

      # The action to take if no topology is successfully fetched in
      # the InitialPeriod.
      # - Fatal: Exit process.
      # - Continue: Log error and continue with execution.
      # (Fatal | Continue) (default Continue)
      FailAction = "Continue"

  [discovery.dynamic]
    # Enable periodic fetching of the dynamic topology. (default false)
    Enable = false

    # Time between two consecutive dynamic topology queries. (default 5s)
    Interval = "5s"

    # Timeout for querying the dynamic topology. (default 1s)
    Timeout = "1s"

    # Require https connection. (default false)
    Https = false

    [discovery.dynamic.connect]
      # Maximum time spent attempting to fetch the topology from the
      # discovery service on start. If no topology is successfully fetched
      # in this period, the FailAction is executed. (default 20s)
      InitialPeriod = "20s"

      # The action to take if no topology is successfully fetched in InitialPeriod.
      # - Fatal: Exit process.
      # - Continue: Log error and continue with execution.
      # (Fatal | Continue) (default Continue)
      FailAction = "Continue"

[br]
  # Enable cpu and memory profiling. (default false)
  Profile = false

  # Action that should be taken when an error occurres during a context rollback.
  # (Fatal | Continue) (default Fatal)
  RollbackFailAction = "Fatal"
`
