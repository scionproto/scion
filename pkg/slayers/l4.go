// Copyright 2022 Anapaya Systems
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

package slayers

import (
	"fmt"
)

type L4ProtocolType uint8

const (
	L4None L4ProtocolType = 0
	L4TCP  L4ProtocolType = 6
	L4UDP  L4ProtocolType = 17
	L4SCMP L4ProtocolType = 202
	L4BFD  L4ProtocolType = 203

	HopByHopClass L4ProtocolType = 200
	End2EndClass  L4ProtocolType = 201

	ExperimentationAndTesting  L4ProtocolType = 253
	ExperimentationAndTesting2 L4ProtocolType = 254
)

func (p L4ProtocolType) String() string {
	switch p {
	case L4None:
		return "None"
	case L4SCMP:
		return "SCMP"
	case L4TCP:
		return "TCP"
	case L4UDP:
		return "UDP"
	case L4BFD:
		return "BFD"
	case HopByHopClass:
		return "HopByHop"
	case End2EndClass:
		return "End2End"
	case ExperimentationAndTesting:
		return "ExperimentationAndTesting"
	case ExperimentationAndTesting2:
		return "ExperimentationAndTesting2"
	}
	return fmt.Sprintf("UNKNOWN (%d)", p)
}
