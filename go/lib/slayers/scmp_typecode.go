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

// SCMP error messages.
const (
	SCMPTypeDestinationUnreachable   = 1
	SCMPTypePacketTooBig             = 2
	SCMPTypeParameterProblem         = 4
	SCMPTypeExternalInterfaceDown    = 5
	SCMPTypeInternalConnectivityDown = 6
)

// Destination unreachable codes
const (
	SCMPCodeNoRoute                   = 0
	SCMPCodeAdminDeny                 = 1
	SCMPCodeBeyondScopeOfSourceAddr   = 2
	SCMPCodeAddressUnreachable        = 3
	SCMPCodePortUnreachable           = 4
	SCMPCodeSourceAddressFailedPolicy = 5
	SCMPCodeRejectRouteToDest         = 6
)

// ParameterProblem
const (
	SCMPCodeErroneousHeaderField = 0
	SCMPCodeUnknownNextHdrType   = 1

	SCMPCodeInvalidCommonHeader  = 16
	SCMPCodeUnknownSCIONVersion  = 17
	SCMPCodeFlowIDRequired       = 18
	SCMPCodeInvalidPacketSize    = 19
	SCMPCodeUnknownPathType      = 20
	SCMPCodeUnknownAddressFormat = 21

	SCMPCodeInvalidAddressHeader      = 32
	SCMPCodeInvalidSourceAddress      = 33
	SCMPCodeInvalidDestinationAddress = 34
	SCMPCodeNonLocalDelivery          = 35

	SCMPCodeInvalidPath              = 48
	SCMPCodeUnknownHopFieldInterface = 49
	SCMPCodeInvalidHopFieldMAC       = 50
	SCMPCodePathExpired              = 51
	SCMPCodeInvalidSegmentChange     = 52

	SCMPCodeInvalidExtensionHeader = 64
	SCMPCodeUnknownHopByHopOption  = 65
	SCMPCodeUnknownEndToEndOption  = 66
)

// SCMP informational messages.
const (
	SCMPTypeEchoRequest       = 128
	SCMPTypeEchoReply         = 129
	SCMPTypeTracerouteRequest = 130
	SCMPTypeTracerouteReply   = 131
)

// SCMPTypeCode represents SCMP type/code case.
type SCMPTypeCode uint16

// Type returns the SCMP type field.
func (a SCMPTypeCode) Type() uint8 {
	return uint8(a >> 8)
}

// Code returns the SCMP code field.
func (a SCMPTypeCode) Code() uint8 {
	return uint8(a)
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
func CreateSCMPTypeCode(typ uint8, code uint8) SCMPTypeCode {
	return SCMPTypeCode(binary.BigEndian.Uint16([]byte{typ, code}))
}

var scmpTypeCodeInfo = map[uint8]struct {
	name  string
	codes map[uint8]string
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
		"ParameterProblem", map[uint8]string{
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
			SCMPCodeUnknownHopFieldInterface:  "UnknownHopFieldInterface",
			SCMPCodeInvalidHopFieldMAC:        "InvalidHopFieldMAC",
			SCMPCodePathExpired:               "PathExpired",
			SCMPCodeInvalidSegmentChange:      "InvalidSegmentChange",
			SCMPCodeInvalidExtensionHeader:    "InvalidExtensionHeader",
			SCMPCodeUnknownHopByHopOption:     "UnknownHopByHopOption",
			SCMPCodeUnknownEndToEndOption:     "UnknownEndToEndOption",
		},
	},
}
