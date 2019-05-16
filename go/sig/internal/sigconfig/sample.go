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

const idSample = "sig4"

const sigSample = `
# ID of the SIG. (required)
ID = "%s"

# The SIG config json file. (required)
SIGConfig = "/etc/scion/sig/sig.json"

# The local IA. (required)
IA = "1-ff00:0:113"

# The bind IP address. (required)
IP = "192.0.2.100"

# Control data port, e.g. keepalives. (default 30256)
CtrlPort = 30256

# Encapsulation data port. (default 30056)
EncapPort = 30056

# SCION dispatcher path. (default "")
Dispatcher = ""

# Name of TUN device to create. (default DefaultTunName)
Tun = "sig"

# Id of the routing table. (default 11)
TunRTableId = 11
`
