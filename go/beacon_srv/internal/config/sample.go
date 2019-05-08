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
