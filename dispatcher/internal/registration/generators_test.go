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

package registration

import (
	"math/rand"
	"net"
	"strconv"

	"github.com/scionproto/scion/pkg/addr"
)

func getRandomUDPAddress() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   getRandomIPv4(),
		Port: getRandomPort(),
	}
}

func getRandomIPv4() net.IP {
	b := byte(rand.Intn(4))
	return net.IP{10, 0, 0, b}
}

func getRandomPort() int {
	return rand.Intn(16)
}

func getRandomValue() string {
	return strconv.Itoa(rand.Intn(1 << 16))
}

func getRandomIA() addr.IA {
	return addr.MustIAFrom(
		addr.ISD(rand.Intn(3)+1),
		addr.AS(rand.Intn(3)+1),
	)
}

func getRandomSVC() addr.SVC {
	switch rand.Intn(2) {
	case 0:
		return addr.SvcNone
	default:
		return addr.SvcCS
	}
}
