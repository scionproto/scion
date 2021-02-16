// Copyright 2020 Anapaya Systems
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

const gatewaySample = `
# ID of the gateway (default "gateway")
id = "gateway"

# The traffic policy file. If not set or empty, the gateway attempts to read the
# policy from the default location. If set, the gateway will read the policy from
# the specified location. If the file does not exist, the gateway will exit with
# an error.
# (default "/share/conf/traffic.policy")
traffic_policy_file = "/share/conf/traffic.policy"

# The IP routing policy file. If set, the gateway will read the policy
# from the specified location. It no file is specified, a default policy
# that rejects all IP prefix announcements is used.
# (default "")
ip_routing_policy_file = ""

# The bind address for control messages. If the host part of the address is
# empty, the gateway infers the address based on the route to the control
# service. If the port is empty, or zero, the default port 30256 is used.
#
# (default ":30256")
#
# Examples:
#  ""                  -> infers the IP and uses default port.
#  ":30299"            -> infers the IP and uses the custom port 30299
#  "192.0.2.100"       -> use the IP and use the default port (192.0.2.100:30256)
#  "192.0.2.100:30299" -> use the address directly
ctrl_addr = ":30256"

# The bind address for encapsulated traffic. If the IP is not specified, the IP
# from the control address is used. If the port is empty, or zero, the default
# port 30056 is used.
#
# (default ":30056")
data_addr = ":30056"
`

const tunnelSample = `
# Name of TUN device to create. (default "sig")
name = "sig"
# Source hint to put to put into the routing table for IPv4 routes.
# (default "")
src_ipv4 = "192.0.2.100"
# Source hint to put to put into the routing table for IPv6 routes.
# (default "")
src_ipv6 = "2001:db8::2:1"
`
