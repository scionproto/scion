// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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
id = "%s"

# The local API socket. (default /run/shm/dispatcher/default.sock)
application_socket = "/run/shm/dispatcher/default.sock"

# File permissions of the ApplicationSocket socket file, in octal. (default "0770")
socket_file_mode = "0770"

# The native port opened by the dispatcher. (default 30041)
underlay_port = 30041

# Remove the socket file (if it exists) on start. (default false)
delete_socket = false
`
