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

package config

const idSample = "sd"

const sdSample = `
# Address to listen on via the reliable socket protocol. If empty,
# a reliable socket server on the default socket is started.
Reliable = "/run/shm/sciond/default.sock"

# Address to listen on for normal unixgram messages. If empty, a
# unixgram server on the default socket is started.
Unix = "/run/shm/sciond/default-unix.sock"

# If set to True, the socket is removed before being created. (default false)
DeleteSocket = false

# Local address to listen on for SCION messages (if Bind is not set),
# and to send out messages to other nodes. (required)
Public = "1-ff00:0:110,[127.0.0.1]:0"

# If set, Bind is the preferred local address to listen on for SCION
# messages.
# Bind = "1-ff00:0:110,[127.0.0.1]:0"

# The time after which segments for a destination are refetched. (default 5m)
QueryInterval = "5m"
`
