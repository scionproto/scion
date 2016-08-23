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

package spkt

import (
//"fmt"
)

const (
	LineLen = 8
)

type L4ProtoType uint8

const (
	L4None L4ProtoType = 0
	L4SCMP L4ProtoType = 1
	L4TCP  L4ProtoType = 6
	L4UDP  L4ProtoType = 17
	L4SSP  L4ProtoType = 152

	HopByHopClass L4ProtoType = 0
	End2EndClass  L4ProtoType = 222
)

var L4Protocols = map[L4ProtoType]bool{
	L4SCMP: true, L4TCP: true, L4UDP: true, L4SSP: true,
}

func (p L4ProtoType) String() string {
	switch p {
	case L4None:
		return "None/HopByHop"
	case L4SCMP:
		return "SCMP"
	case L4TCP:
		return "TCP"
	case L4UDP:
		return "UDP"
	case L4SSP:
		return "SSP"
	case End2EndClass:
		return "End2End"
	}
	return "UNKNOWN"
}

type ExtnType struct {
	Class L4ProtoType
	Type  uint8
}

var (
	ExtnTracerouteType = ExtnType{HopByHopClass, 0}
	ExtnSIBRAType      = ExtnType{HopByHopClass, 1}
	ExtnSCMPType       = ExtnType{HopByHopClass, 2}
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
	case ExtnPathTransType:
		return "PathTrans"
	case ExtnPathProbeType:
		return "PathProbe"
	}
	return "UNKNOWN"
}
