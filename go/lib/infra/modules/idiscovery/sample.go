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

package idiscovery

const staticSample = `
# Enable periodic fetching of the static topology. (default false)
Enable = false

# Time between two consecutive static topology queries. (default 5m)
Interval = "5m"

# Timeout for querying the static topology. (default 1s)
Timeout = "1s"

# Require https connection. (default false)
Https = false

# Filename where the updated static topologies are written. In case of the
# empty string, the updated topologies are not written. (default "")
Filename = ""
`

const dynamicSample = `
# Enable periodic fetching of the dynamic topology. (default false)
Enable = false

# Time between two consecutive dynamic topology queries. (default 5s)
Interval = "5s"

# Timeout for querying the dynamic topology. (default 1s)
Timeout = "1s"

# Require https connection. (default false)
Https = false
`

const connectSample = `
# Maximum time spent attempting to fetch the topology from the
# discovery service on start. If no topology is successfully fetched
# in this period, the FailAction is executed. (default 20s)
InitialPeriod = "20s"

# The action to take if no topology is successfully fetched in
# the InitialPeriod.
# - Fatal: Exit process.
# - Continue: Log error and continue with execution.
# (Fatal | Continue) (default Continue)
FailAction = "Continue"
`
