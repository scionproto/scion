// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
)

type HostAddrType uint8

const (
	HostTypeNone HostAddrType = iota
	HostTypeIPv4
	HostTypeIPv6
	HostTypeSVC
)

func (t HostAddrType) String() string {
	switch t {
	case HostTypeNone:
		return "None"
	case HostTypeIPv4:
		return "IPv4"
	case HostTypeIPv6:
		return "IPv6"
	case HostTypeSVC:
		return "SVC"
	}
	return fmt.Sprintf("UNKNOWN (%d)", t)
}

const (
	HostLenNone = 0
	HostLenIPv4 = net.IPv4len
	HostLenIPv6 = net.IPv6len
	HostLenSVC  = 2
)

const SVCMcast = 0x8000

const (
	ErrorBadHostAddrType = "Unsupported host address type"
)

const (
	SvcBS   HostSVC = 0x0000
	SvcPS   HostSVC = 0x0001
	SvcCS   HostSVC = 0x0002
	SvcSB   HostSVC = 0x0003
	SvcSIG  HostSVC = 0x0004
	SvcNone HostSVC = 0xffff
)

type HostAddr interface {
	Size() int
	Type() HostAddrType
	Pack() common.RawBytes
	IP() net.IP
	Copy() HostAddr
	Eq(HostAddr) bool
	fmt.Stringer
}

var _ HostAddr = (HostNone)(nil)

type HostNone net.IP

func (h HostNone) Size() int {
	return HostLenNone
}

func (h HostNone) Type() HostAddrType {
	return HostTypeNone
}

func (h HostNone) Pack() common.RawBytes {
	return common.RawBytes{}
}

func (h HostNone) IP() net.IP {
	return nil
}

func (h HostNone) Copy() HostAddr {
	return HostNone{}
}

func (h HostNone) Eq(o HostAddr) bool {
	_, ok := o.(HostNone)
	return ok
}

func (h HostNone) String() string {
	return "<None>"
}

var _ HostAddr = (HostIPv4)(nil)

type HostIPv4 net.IP

func (h HostIPv4) Size() int {
	return HostLenIPv4
}

func (h HostIPv4) Type() HostAddrType {
	return HostTypeIPv4
}

func (h HostIPv4) Pack() common.RawBytes {
	return common.RawBytes(h.IP())
}

func (h HostIPv4) IP() net.IP {
	// XXX(kormat): ensure the reply is the 4-byte representation.
	return net.IP(h).To4()
}

func (h HostIPv4) Copy() HostAddr {
	return HostIPv4(append(net.IP(nil), h...))
}

func (h HostIPv4) Eq(o HostAddr) bool {
	ha, ok := o.(HostIPv4)
	return ok && net.IP(h).Equal(net.IP(ha))
}

func (h HostIPv4) String() string {
	return h.IP().String()
}

var _ HostAddr = (HostIPv6)(nil)

type HostIPv6 net.IP

func (h HostIPv6) Size() int {
	return HostLenIPv6
}

func (h HostIPv6) Type() HostAddrType {
	return HostTypeIPv6
}

func (h HostIPv6) Pack() common.RawBytes {
	return common.RawBytes(h)[:HostLenIPv6]
}

func (h HostIPv6) IP() net.IP {
	return net.IP(h)
}

func (h HostIPv6) Copy() HostAddr {
	return HostIPv6(append(net.IP(nil), h...))
}

func (h HostIPv6) Eq(o HostAddr) bool {
	ha, ok := o.(HostIPv6)
	return ok && net.IP(h).Equal(net.IP(ha))
}

func (h HostIPv6) String() string {
	return h.IP().String()
}

var _ HostAddr = (*HostSVC)(nil)

type HostSVC uint16

// HostSVCFromString returns the SVC address corresponding to str. For anycast
// SVC addresses, use BS_A, PS_A, CS_A, and SB_A; shorthand versions without
// the _A suffix (e.g., PS) also return anycast SVC addresses. For multicast,
// use BS_M, PS_M, CS_M, and SB_M.
func HostSVCFromString(str string) HostSVC {
	var m HostSVC
	switch {
	case strings.HasSuffix(str, "_A"):
		str = strings.TrimSuffix(str, "_A")
	case strings.HasSuffix(str, "_M"):
		str = strings.TrimSuffix(str, "_M")
		m = SVCMcast
	}
	switch str {
	case "BS":
		return SvcBS | m
	case "PS":
		return SvcPS | m
	case "CS":
		return SvcCS | m
	case "SB":
		return SvcSB | m
	case "SIG":
		return SvcSIG | m
	default:
		return SvcNone
	}
}

func (h HostSVC) Size() int {
	return HostLenSVC
}

func (h HostSVC) Type() HostAddrType {
	return HostTypeSVC
}

func (h HostSVC) Pack() common.RawBytes {
	out := make(common.RawBytes, HostLenSVC)
	binary.BigEndian.PutUint16(out, uint16(h))
	return out
}

func (h HostSVC) IP() net.IP {
	return nil
}

func (h HostSVC) IsMulticast() bool {
	return (h & SVCMcast) != 0
}

func (h HostSVC) Base() HostSVC {
	return h & ^HostSVC(SVCMcast)
}

func (h HostSVC) Multicast() HostSVC {
	return h | HostSVC(SVCMcast)
}

func (h HostSVC) Copy() HostAddr {
	return h
}

func (h HostSVC) Eq(o HostAddr) bool {
	ha, ok := o.(HostSVC)
	return ok && h == ha
}

func (h HostSVC) String() string {
	var name string
	switch h.Base() {
	case SvcBS:
		name = "BS"
	case SvcPS:
		name = "PS"
	case SvcCS:
		name = "CS"
	case SvcSB:
		name = "SB"
	case SvcSIG:
		name = "SIG"
	default:
		name = "UNKNOWN"
	}
	cast := 'A'
	if h.IsMulticast() {
		cast = 'M'
	}
	return fmt.Sprintf("%v %c (0x%04x)", name, cast, uint16(h))
}

func HostFromRaw(b common.RawBytes, htype HostAddrType) (HostAddr, error) {
	switch htype {
	case HostTypeNone:
		return HostNone{}, nil
	case HostTypeIPv4:
		return HostIPv4(b[:HostLenIPv4]), nil
	case HostTypeIPv6:
		return HostIPv6(b[:HostLenIPv6]), nil
	case HostTypeSVC:
		return HostSVC(binary.BigEndian.Uint16(b)), nil
	default:
		return nil, common.NewBasicError(ErrorBadHostAddrType, nil, "type", htype)
	}
}

func HostFromIP(ip net.IP) HostAddr {
	if ip4 := ip.To4(); ip4 != nil {
		return HostIPv4(ip4)
	}
	return HostIPv6(ip)
}

func HostFromIPStr(s string) HostAddr {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return HostFromIP(ip)
}

func HostLen(htype HostAddrType) (uint8, error) {
	var length uint8
	switch htype {
	case HostTypeNone:
		length = HostLenNone
	case HostTypeIPv4:
		length = HostLenIPv4
	case HostTypeIPv6:
		length = HostLenIPv6
	case HostTypeSVC:
		length = HostLenSVC
	default:
		return 0, common.NewBasicError(ErrorBadHostAddrType, nil, "type", htype)
	}
	return length, nil
}

func HostTypeCheck(t HostAddrType) bool {
	switch t {
	case HostTypeIPv6, HostTypeIPv4, HostTypeSVC:
		return true
	}
	return false
}
