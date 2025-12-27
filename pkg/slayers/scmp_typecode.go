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

package slayers

import (
	"encoding/binary"
	"fmt"
)

// SCMPType is the type of the SCMP type code.
type SCMPType uint8

// SCMPCode is the code of the SCMP type code.
type SCMPCode uint8

// SCMP error messages.
const (
	SCMPTypeDestinationUnreachable   SCMPType = 1
	SCMPTypePacketTooBig             SCMPType = 2
	SCMPTypeParameterProblem         SCMPType = 4
	SCMPTypeExternalInterfaceDown    SCMPType = 5
	SCMPTypeInternalConnectivityDown SCMPType = 6
)

// Destination unreachable codes
const (
	SCMPCodeNoRoute                   SCMPCode = 0
	SCMPCodeAdminDeny                 SCMPCode = 1
	SCMPCodeBeyondScopeOfSourceAddr   SCMPCode = 2
	SCMPCodeAddressUnreachable        SCMPCode = 3
	SCMPCodePortUnreachable           SCMPCode = 4
	SCMPCodeSourceAddressFailedPolicy SCMPCode = 5
	SCMPCodeRejectRouteToDest         SCMPCode = 6
)

// ParameterProblem
const (
	SCMPCodeErroneousHeaderField SCMPCode = 0
	SCMPCodeUnknownNextHdrType   SCMPCode = 1

	SCMPCodeInvalidCommonHeader  SCMPCode = 16
	SCMPCodeUnknownSCIONVersion  SCMPCode = 17
	SCMPCodeFlowIDRequired       SCMPCode = 18
	SCMPCodeInvalidPacketSize    SCMPCode = 19
	SCMPCodeUnknownPathType      SCMPCode = 20
	SCMPCodeUnknownAddressFormat SCMPCode = 21

	SCMPCodeInvalidAddressHeader      SCMPCode = 32
	SCMPCodeInvalidSourceAddress      SCMPCode = 33
	SCMPCodeInvalidDestinationAddress SCMPCode = 34
	SCMPCodeNonLocalDelivery          SCMPCode = 35

	SCMPCodeInvalidPath            SCMPCode = 48
	SCMPCodeUnknownHopFieldIngress SCMPCode = 49
	SCMPCodeUnknownHopFieldEgress  SCMPCode = 50
	SCMPCodeInvalidHopFieldMAC     SCMPCode = 51
	SCMPCodePathExpired            SCMPCode = 52
	SCMPCodeInvalidSegmentChange   SCMPCode = 53

	SCMPCodeInvalidExtensionHeader SCMPCode = 64
	SCMPCodeUnknownHopByHopOption  SCMPCode = 65
	SCMPCodeUnknownEndToEndOption  SCMPCode = 66

	SCMPCodeReservationExpired SCMPCode = 71
)

// SCMP informational messages.
const (
	SCMPTypeEchoRequest       SCMPType = 128
	SCMPTypeEchoReply         SCMPType = 129
	SCMPTypeTracerouteRequest SCMPType = 130
	SCMPTypeTracerouteReply   SCMPType = 131
)

// SCMPTypeCode represents SCMP type/code case.
type SCMPTypeCode uint16

// Type returns the SCMP type field.
func (a SCMPTypeCode) Type() SCMPType {
	return SCMPType(a >> 8)
}

// Code returns the SCMP code field.
func (a SCMPTypeCode) Code() SCMPCode {
	return SCMPCode(a)
}

// InfoMsg indicates if the SCMP message is an SCMP informational message.
func (a SCMPTypeCode) InfoMsg() bool {
	return a.Type() > 127
}

func (a SCMPTypeCode) String() string {
	t, c := a.Type(), a.Code()
	info, ok := scmpTypeCodeInfo[t]
	if !ok {
		return fmt.Sprintf("%d(%d)", t, c)
	}
	if info.codes == nil && c == 0 {
		return info.name
	}
	code, ok := info.codes[c]
	if !ok {
		return fmt.Sprintf("%s(Code: %d)", info.name, c)
	}
	return fmt.Sprintf("%s(%s)", info.name, code)
}

// SerializeTo writes the SCMPTypeCode value to the buffer.
func (a SCMPTypeCode) SerializeTo(bytes []byte) {
	binary.BigEndian.PutUint16(bytes, uint16(a))
}

// CreateSCMPTypeCode is a convenience function to create an SCMPTypeCode
func CreateSCMPTypeCode(typ SCMPType, code SCMPCode) SCMPTypeCode {
	return SCMPTypeCode(binary.BigEndian.Uint16([]byte{uint8(typ), uint8(code)}))
}

var scmpTypeCodeInfo = map[SCMPType]struct {
	name  string
	codes map[SCMPCode]string
}{
	SCMPTypeDestinationUnreachable:   {name: "DestinationUnreachable"},
	SCMPTypeExternalInterfaceDown:    {name: "ExternalInterfaceDown"},
	SCMPTypeInternalConnectivityDown: {name: "InternalConnectivityDown"},
	SCMPTypePacketTooBig:             {name: "PacketTooBig"},
	SCMPTypeEchoRequest:              {name: "EchoRequest"},
	SCMPTypeEchoReply:                {name: "EchoReply"},
	SCMPTypeTracerouteRequest:        {name: "TracerouteRequest"},
	SCMPTypeTracerouteReply:          {name: "TracerouteReply"},
	SCMPTypeParameterProblem: {
		"ParameterProblem", map[SCMPCode]string{
			SCMPCodeErroneousHeaderField:      "ErroneousHeaderField",
			SCMPCodeUnknownNextHdrType:        "UnknownNextHdrType",
			SCMPCodeInvalidCommonHeader:       "InvalidCommonHeader",
			SCMPCodeUnknownSCIONVersion:       "UnknownSCIONVersion",
			SCMPCodeFlowIDRequired:            "FlowIDRequired",
			SCMPCodeInvalidPacketSize:         "InvalidPacketSize",
			SCMPCodeUnknownPathType:           "UnknownPathType",
			SCMPCodeUnknownAddressFormat:      "UnknownAddressFormat",
			SCMPCodeInvalidAddressHeader:      "InvalidAddressHeader",
			SCMPCodeInvalidSourceAddress:      "InvalidSourceAddress",
			SCMPCodeInvalidDestinationAddress: "InvalidDestinationAddress",
			SCMPCodeNonLocalDelivery:          "NonLocalDelivery",
			SCMPCodeInvalidPath:               "InvalidPath",
			SCMPCodeUnknownHopFieldIngress:    "UnknownHopFieldIngressInterface",
			SCMPCodeUnknownHopFieldEgress:     "UnknownHopFieldEgressInterface",
			SCMPCodeInvalidHopFieldMAC:        "InvalidHopFieldMAC",
			SCMPCodePathExpired:               "PathExpired",
			SCMPCodeInvalidSegmentChange:      "InvalidSegmentChange",
			SCMPCodeInvalidExtensionHeader:    "InvalidExtensionHeader",
			SCMPCodeUnknownHopByHopOption:     "UnknownHopByHopOption",
			SCMPCodeUnknownEndToEndOption:     "UnknownEndToEndOption",
		},
	},
}
