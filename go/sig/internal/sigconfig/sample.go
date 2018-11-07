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

package sigconfig

const Sample = `
[sig]
  # ID of the SIG (Required.)
  ID = "sig4"

  # The SIG config json file. (Required.)
  Config = "/etc/scion/sig/sig.json"

  # The local IA (Required.)
  IA = "1-ff00:0:113"

  # The bind IP address (Required.)
  IP = "168.10.20.15"

  # Control data port, e.g. keepalives. (Default: DefaultCtrlPort)
  CtrlPort = 10081

  # Encapsulation data port. (Default: DefaultEncapPort)
  EncapPort = 10080

  # SCIOND socket path. (Default: default sciond path)
  Sciond = ""

  # SCION dispatcher path. (Default: "")
  Dispatcher = ""

  # Name of TUN device to create. (Default: DefaultTunName)
  Tun = "sig"

[logging]
[logging.file]
  # Location of the logging file.
  Path = "/var/log/scion/sig4.log"

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

`
