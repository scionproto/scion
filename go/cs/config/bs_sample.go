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

const BSSample = `
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

# The revocation TTL. (default 10s)
RevTTL = "10s"

# The amount of time before the expiry of an existing revocation where the revoker can reissue a
# new revocation. (default 5s)
RevOverlap = "5s"
`

const PoliciesSample = `
# Output a sample policy file by providing the -help-policy flag.

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

# The file path for the hidden path registration policy. In case of the empty string,
# no hidden path functionality is used.
# (default "")
HiddenPathRegistration = ""
`
