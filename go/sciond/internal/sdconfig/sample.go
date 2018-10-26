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

package sdconfig

const Sample = `[general]
  # The ID of the service.
  ID = "sd"

  # Directory for loading AS information, certs, keys, path policy, topology.
  ConfigDir = "/etc/scion"

  # Topology file. If not specified, topology.json is loaded from the config
  # directory.
  # Topology = "/etc/scion/topology.json"

  # ReconnectToDispatcher can be set to true to enable the snetproxy reconnecter.
  # ReconnectToDispatcher = true

[logging]
  [logging.file]
    # Location of the logging file.
    Path = "/var/log/scion/sd.log"

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
  TrustDB = "/var/lib/scion/spki/sd.trust.db"

[sd]
  # Address to listen on via the reliable socket protocol. If empty,
  # a reliable socket server on the default socket is started.
  Reliable = "/run/shm/sciond/default.sock"

  # Address to listen on for normal unixgram messages. If empty, a
  # unixgram server on the default socket is started.
  Unix = "/run/shm/sciond/default-unix.sock"

  # If set to True, the socket is removed before being created. (default false)
  DeleteSocket = false

  # Local address to listen on for SCION messages (if Bind is not set),
  # and to send out messages to other nodes.
  Public = "1-ff00:0:110,[127.0.0.1]:0"

  # If set, Bind is the preferred local address to listen on for SCION
  # messages.
  # Bind = "1-ff00:0:110,[127.0.0.1]:0"

  # The time after which segments for a destination are refetched. (default 5m)
  QueryInterval = "5m"

  [sd.PathDB]
    # The type of pathdb backend
    Backend = "sqlite"
    # Path to the path database.
    Connection = "/var/lib/scion/sd.path.db"

  [sd.RevCache]
    Backend = "mem"

`
