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

const idSample = "dispatcher"

const dispSample = `
# ID of the Dispatcher. (required)
ID = "%s"

# ApplicationSocket is the local API socket. (default /run/shm/dispatcher/default.sock)
ApplicationSocket = "/run/shm/dispatcher/default.sock"

# OverlayPort is the native port opened by the dispatcher. (default 30041)
OverlayPort = 30041

# PerfData starts the pprof HTTP server on the specified address.
# (host:port or ip:port or :port) If not set, the server is not started.
PerfData = ""

# Set DeleteSock to true to have the Dispatcher remove the socket file (if it
# exists) on start. (default false)
DeleteSocket = false
`
