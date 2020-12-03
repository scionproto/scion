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

const idSample = "bootstrapper"

const bootstrapperSample = `
# The folder where the retrieved topology and certificates are stored (default ".")
sciond_config_dir = "."

# Discovery mechanisms
[mock]
	# Whether to enable the fake discovery or not (default false)
	# This discovery mechanisms is used for testing purposes
	enable = false
	# The address to return when simulating a network discovery (default "")
	address = ""
[dhcp]
	# Whether to enable DHCP discovery or not (default false)
	enable = false
[dnssd]
	# Whether to enable DNS SRV discovery or not (default false)
	enable_srv = true
	# Whether to enable DNS-SD discovery or not (default false)
	enable_sd = true
	# Whether to enable DNS-NAPTR discovery or not (default false)
	enable_naptr = true
[mdns]
	# Whether to enable mDNS discovery or not (default false)
  	enable = true
`
