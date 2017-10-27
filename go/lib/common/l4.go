// Copyright 2016 ETH Zurich
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

package common

import (
	"fmt"
)

type L4ProtocolType uint8

const (
	L4None L4ProtocolType = 0
	L4SCMP L4ProtocolType = 1
	L4TCP  L4ProtocolType = 6
	L4UDP  L4ProtocolType = 17

	HopByHopClass L4ProtocolType = 0
	End2EndClass  L4ProtocolType = 222
)

var L4Protocols = map[L4ProtocolType]bool{
	L4SCMP: true, L4TCP: true, L4UDP: true,
}

func (p L4ProtocolType) String() string {
	switch p {
	case L4None:
		return "None/HopByHop"
	case L4SCMP:
		return "SCMP"
	case L4TCP:
		return "TCP"
	case L4UDP:
		return "UDP"
	case End2EndClass:
		return "End2End"
	}
	return fmt.Sprintf("UNKNOWN (%d)", p)
}
