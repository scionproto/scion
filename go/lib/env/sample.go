// Copyright 2019 Anapaya Systems
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

package env

const generalSample = `
# The ID of the service. (required)
ID = "%s"

# Directory for loading AS information, certs, keys, path policy, topology.
ConfigDir = "/etc/scion"

# Topology file. If not specified, it is loaded from the config directory.
# (default ConfigDir/topology.json)
Topology = "/etc/scion/topology.json"

# Enable the snetproxy reconnecter. (default false)
ReconnectToDispatcher = false
`

const sciondClientSample = `
# The Sciond path. (default sciond.DefaultSCIONDPath)
Path = "/run/shm/sciond/default.sock"

# Maximum time spent attempting to connect to sciond on start. (default 20s)
InitialConnectPeriod = "20s"
`

const loggingFileSample = `
# Location of the logging file. If not specified, logging to file is disabled.
Path = "/var/log/scion/%s.log"

# File logging level. (trace|debug|info|warn|error|crit) (default debug)
Level = "debug"

# Max size of log file in MiB. (default 50)
Size = 50

# Max age of log file in days. (default 7)
MaxAge = 7

# Maximum number of log files to retain. (default 10)
MaxBackups = 10

# How frequently to flush to the log file, in seconds. If 0, all messages
# are immediately flushed. If negative, messages are never flushed
# automatically. (default 5)
FlushInterval = 5
`

const loggingConsoleSample = `
# Console logging level (trace|debug|info|warn|error|crit) (default crit)
Level = "crit"
`

const metricsSample = `
# The address to export prometheus metrics on (host:port or ip:port or :port).
# If not set, metrics are not exported. (default "")
Prometheus = ""
`
