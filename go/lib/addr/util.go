// Copyright 2018 ETH Zurich
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

package addr

import "net"

// IsIPv4 returns whether the ip is IPv4 or not.
// This has the side effect in Go that if the ip passed was the direct result
// of net.IPv4(), it will fail to detect it as an IPv4 given that the
// underlying byte buffer is 16B.
func IsIPv4(ip net.IP) bool {
	return len(ip) == net.IPv4len
}

func IsIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}
