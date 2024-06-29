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
`

const featuresSample = `
# Feature flags are various boolean properties as defined in go/lib/env/features.go
`

const daemonSample = `
# Address of the SCIOND server the client should connect to. (default 127.0.0.1:30255)
address = "127.0.0.1:30255"

# Maximum time spent attempting to connect to SCION Daemon on start. (default 20s)
initial_connect_period = "20s"
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
