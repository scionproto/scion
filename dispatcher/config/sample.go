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

# The underlay IP address opened by the dispatcher. (default ::)
# underlay_addr = "::"

# ServiceAddresses is the map of IA,SVC -> underlay UDP/IP address.
# The map should be configured provided that the shim dispatcher runs colocated to such
# mapped services, e.g., the shim dispatcher runs on the same host,
# where the CS for the local IA runs. 
# For other use cases it can be ignored.
[dispatcher.service_addresses]
"1-ff00:0:110,CS" = "[fd00:f00d:cafe::7f00:14]:31000"
"1-ff00:0:110,DS" = "[fd00:f00d:cafe::7f00:14]:31000"
"1-ff00:0:120,CS" = "127.0.0.68:31008"
"1-ff00:0:120,DS" = "127.0.0.68:31008"
"1-ff00:0:130,CS" = "[fd00:f00d:cafe::7f00:2b]:31016"
"1-ff00:0:130,DS" = "[fd00:f00d:cafe::7f00:2b]:31016"
`
