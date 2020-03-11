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
id = "%s"

# Directory for loading AS information, certs, keys, path policy, topology.
config_dir = "/etc/scion"

# Enable the snetproxy reconnecter. (default false)
reconnect_to_dispatcher = false
`

const featuresSample = `
# Feature flags are various boolean properties as defined in go/lib/env/features.go
`

const sciondClientSample = `
# Address of the SCIOND server the client should connect to.
address = "127.0.0.1:30255"

# Maximum time spent attempting to connect to sciond on start. (default 20s)
initial_connect_period = "20s"

# Maximum numer of paths provided by SCIOND.
# Zero means that all the paths should be provided. (default 0)
path_count = 0
`

const metricsSample = `
# The address to export prometheus metrics on (host:port or ip:port or :port).
# The prometheus metrics can be found under /metrics, furthermore pprof
# endpoints are exposed see (https://golang.org/pkg/net/http/pprof/).
# If not set, metrics are not exported. (default "")
prometheus = ""
`

const tracingSample = `
# Enable the tracing. (default false)
enabled = false
# Enable debug mode. (default false)
debug = false
# Address of the local agent that handles the reported traces.
# (default: localhost:6831)
agent = "localhost:6831"
`

const quicSample = `
# The address to start a QUIC server on (ip:port). If not set, a QUIC server is
# not started. (default "")
address = ""

# Certificate file to use for authenticating QUIC connections.
cert_file = "/etc/scion/quic/tls.pem"

# Key file to use for authenticating QUIC connections.
key_file = "/etc/scion/quic/tls.key"

# Enables SVC resolution for traffic to SVC
# destinations in a way that is also compatible with control plane servers
# that do not implement the SVC Resolution Mechanism. The value represents
# the percentage of time, out of the total available context timeout,
# spent attempting to perform SVC resolution. If SVCResolutionFraction is
# 0 or less, SVC resolution is never attempted. If it is between 0 and 1,
# the remaining context timeout is multiplied by the value, and that
# amount of time is spent waiting for an SVC resolution reply from the
# server. If this times out, the data packet is sent with an SVC
# destination. If the value is 1 or more, then legacy behavior is
# disabled, and data packets are never sent to SVC destinations unless the
# resolution step is successful.
resolution_fraction = 0.0
`
