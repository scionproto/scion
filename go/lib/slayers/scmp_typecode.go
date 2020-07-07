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

func (a SCMPTypeCode) String() string {
	t, c := a.Type(), a.Code()
	return fmt.Sprintf("%d(%d)", t, c)
}

// SerializeTo writes the SCMPTypeCode value to the buffer.
func (a SCMPTypeCode) SerializeTo(bytes []byte) {
	binary.BigEndian.PutUint16(bytes, uint16(a))
}

// CreateSCMPTypeCode is a convenience function to create an SCMPTypeCode
func CreateSCMPTypeCode(typ uint8, code uint8) SCMPTypeCode {
	return SCMPTypeCode(binary.BigEndian.Uint16([]byte{typ, code}))
}

// TODO(karampok). bring a better string representation
// as in https://github.com/google/gopacket/blob/9f64f498dcfc67d74ca3eb8384ee77ff9f860d7e/layers/icmp6.go#L64-L120
