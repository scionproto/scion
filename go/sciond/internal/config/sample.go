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

# File permissions of both the Reliable and Unix socket files, in octal. (default "0770")
SocketFileMode = "0770"

# If set to True, the socket is removed before being created. (default false)
DeleteSocket = false

# Listening address to register with the local dispatcher
# in order to receive and send SCION messages to other nodes. (required)
Public = "127.0.0.1:0"

# The time after which segments for a destination are refetched. (default 5m)
QueryInterval = "5m"
`
