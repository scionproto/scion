// Copyright 2018 ETH Zurich
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

package config

const Sample = `
[dispatcher]
  # ID of the Dispatcher (required)
  ID = "disp"

  # ApplicationSocket is the local API socket (default /run/shm/dispatcher/default.sock)
  ApplicationSocket = "/run/shm/dispatcher/default.sock"

  # OverlayPort is the native port opened by the dispatcher (default 30041)
  OverlayPort = 30041

  # PerfData starts the pprof HTTP server on the specified address. If not set,
  # the server is not started.
  # PerfData = "127.0.0.1:6060"

  # Set DeleteSock to true to have the Dispatcher remove the socket file (if it
  # exists) on start (default false)
  DeleteSocket = false

[logging]
  [logging.file]
    # Location of the logging file.
    Path = "/var/log/scion/dispatcher.log"

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
  # Prometheus is the address to export prometheus metrics on. If not set,
  # metrics are not exported.
  # Prometheus = "127.0.0.1:8000"
`
