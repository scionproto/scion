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

package csconfig

const Sample = `[general]
  # The ID of the service. This is used to choose the relevant portion of the
  # topology file for some services.
  ID = "cs-1"

  # Directory for loading AS information, certs, keys, path policy, topology.
  ConfigDir = "/etc/scion"

  # Topology file. If not specified, topology.json is loaded from the config
  # directory.
  # Topology = "/etc/scion/topology.json"

  # ReconnectToDispatcher can be set to true to enable the snetproxy reconnecter.
  # ReconnectToDispatcher = true

[sd_client]
  # Sciond path. It defaults to sciond.DefaultSCIONDPath.
  # Path = "/run/shm/sciond/default.sock"

  # Maximum time spent attempting to connect to sciond on start. (default 20s)
  # InitialConnectPeriod = "20s"

[logging]
  [logging.file]
    # Location of the logging file.
    Path = "/var/log/scion/cs-1.log"

    # File logging level (trace|debug|info|warn|error|crit) (default debug)
    Level = "debug"

    # Max size of log file in MiB (default 50)
    # Size = 50

    # Max age of log file in days (default 7)
    # MaxAge = 7

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

[trust]
  # Database for trust information. If a file already exists, it is treated as
  # initial trust information. If a file does not exist, it is created from the
  # initial information found under ConfigDir/certs.
  TrustDB = "/var/lib/scion/spki/cs-1.trust.db"

[cs]
  # Time between starting reissue requests and leaf cert expiration. If not
  # specified, this is set to PathSegmentTTL.
  LeafReissueLeadTime = "6h"

  # Time between self issuing core cert and core cert expiration. If not
  # specified, this is set to the default leaf certificate validity time.
  IssuerReissueLeadTime = "73h"

  # Interval between two consecutive reissue requests. Default is 10 seconds.
  ReissueRate = "10s"

  # Timeout for resissue request.  Default is 5 seconds.
  ReissueTimeout = "5s"

  # Whether automatic reissuing is enabled. Default is false.
  AutomaticRenewal = false
`
