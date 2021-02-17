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

package config

const bsSample = `
# The interval between originating beacons. (default 5s)
origination_interval = "5s"

# The interval between propagating beacons. (default 5s)
propagation_interval = "5s"

# The interval between registering beacons. (default 5s)
registration_interval = "5s"
`

const policiesSample = `
# Output a sample policy file by providing the -help-policy flag.

# The file path for the propagation policy. In case of the empty string,
# the default policy is used. (default "")
propagation = ""

# The file path for the core registration policy. In case of the empty string,
# the default policy is used. In a non-core beacon server, this field is ignored.
# (default "")
core_registration = ""

# The file path for the up registration policy. In case of the empty string,
# the default policy is used. In a core beacon server, this field is ignored.
# (default "")
up_registration = ""

# The file path for the down registration policy. In case of the empty string,
# the default policy is used. In a core beacon server, this field is ignored.
# (default "")
down_registration = ""
`
