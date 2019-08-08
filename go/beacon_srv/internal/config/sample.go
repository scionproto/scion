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

const idSample = "bs-1"

const bsconfigSample = `
# The interval between sending interface keepalives. (default 1s)
KeepaliveInterval = "1s"

# The timeout until an interface that has not received keepalives
# is considered expired. (default 3s)
KeepaliveTimeout = "3s"

# The interval between originating beacons. (default 5s)
OriginationInterval = "5s"

# The interval between propagating beacons. (default 5s)
PropagationInterval = "5s"

# The interval between registering beacons. (default 5s)
RegistrationInterval = "5s"

# The interval between checking for expired interfaces to revoke. (default 200ms)
ExpiredCheckInterval = "200ms"
`

const policiesSample = `
# The file path for the propagation policy. In case of the empty string, 
# the default policy is used. (default "")
Propagation = ""

# The file path for the core registration policy. In case of the empty string, 
# the default policy is used. In a non-core beacon server, this field is ignored.
# (default "")
CoreRegistration = ""

# The file path for the up registration policy. In case of the empty string, 
# the default policy is used. In a core beacon server, this field is ignored.
# (default "")
UpRegistration = ""

# The file path for the down registration policy. In case of the empty string, 
# the default policy is used. In a core beacon server, this field is ignored.
# (default "")
DownRegistration = ""
`

const hpGroupsSample = `
# The hidden path groups known to this BS
# Map from GroupId to location of group configuration file
[hpGroups.ff00_0_110-69b5]
CfgFilePath = "path/to/HPGCfg_ff00_0_110-69b5.json"

[hpGroups.ffaa_0_222-abcd]
CfgFilePath = "path/to/HPGCfg_ffa_0_222-abcd.json"
`

const regPoliciesSample = `
# The default action to perform for segments not explicitly listed.
# Valid options are "register" and "discard".
# (default "register")
DefaultAction = "register"

# Speciefies wether the same segment can be 
# registered as hidden and public.
# (default false)
HiddenAndPublic = false

	[segmentRegistration.ps.2]
		# Wether to register this segment as down-segment
		# at the core PS (default false)
		RegDown = false

		# Wether to register this segment as up-segment
		# at the local PS (default false)
		RegUp = false

		# Maximal time after which segment expires
		#(default "1h")
		MaxExpiration = "1h"

	[segmentRegistration.hps.2.ff00_0_110-69b5]
		# Wether to register this segment as down-segment
		# at the remote HPS of the specified HPGroup
		#(default false)
		RegDown = false

		# Wether to register this segment as hidden up-segment
		# at the local HPS
		#(default false)
		RegUp = false

		# Maximal time after which segment expires
		#(default "1h")
		MaxExpiration = "1h"
`
