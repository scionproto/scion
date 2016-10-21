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

type ExtnType struct {
	Class L4ProtocolType
	Type  uint8
}

var (
	ExtnTracerouteType = ExtnType{HopByHopClass, 0}
	ExtnSIBRAType      = ExtnType{HopByHopClass, 1}
	ExtnSCMPType       = ExtnType{HopByHopClass, 2}
	ExtnOneHopPathType = ExtnType{HopByHopClass, 3}
	ExtnPathTransType  = ExtnType{End2EndClass, 0}
	ExtnPathProbeType  = ExtnType{End2EndClass, 1}
)

func (e ExtnType) String() string {
	switch e {
	case ExtnTracerouteType:
		return "Traceroute"
	case ExtnSIBRAType:
		return "SIBRA"
	case ExtnSCMPType:
		return "SCMP"
	case ExtnOneHopPathType:
		return "OneHopPath"
	case ExtnPathTransType:
		return "PathTrans"
	case ExtnPathProbeType:
		return "PathProbe"
	}
	return fmt.Sprintf("UNKNOWN (%d)", e)
}
