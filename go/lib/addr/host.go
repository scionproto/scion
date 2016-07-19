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

package addr

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	HostTypeNone = iota
	HostTypeIPv4
	HostTypeIPv6
	HostTypeSVC
)

const (
	HostLenNone = 0
	HostLenIPv4 = net.IPv4len
	HostLenIPv6 = net.IPv6len
	HostLenSVC  = 2
)

const SVCMcast = 0x8000

const (
	ErrorUnknownHostAddrType = "Unknown host address type"
)

var (
	SvcBS   = HostSVC(0x0000)
	SvcPS   = HostSVC(0x0001)
	SvcCS   = HostSVC(0x0002)
	SvcSB   = HostSVC(0x0003)
	SvcNone = HostSVC(0xffff)
)

type HostAddr interface {
	Size() int
	Type() uint8
	Pack() util.RawBytes
	IP() net.IP
	fmt.Stringer
}

// Host None type
// *****************************************
type HostNone net.IP

func (h HostNone) Size() int {
	return HostLenNone
}

func (h HostNone) Type() uint8 {
	return HostTypeNone
}

func (h HostNone) Pack() util.RawBytes {
	return util.RawBytes{}
}

func (h HostNone) IP() net.IP {
	return nil
}

func (h HostNone) String() string {
	return "<None>"
}

// Host IPv4 type
// *****************************************
type HostIPv4 net.IP

func (h *HostIPv4) Size() int {
	return HostLenIPv4
}

func (h *HostIPv4) Type() uint8 {
	return HostTypeIPv4
}

func (h *HostIPv4) Pack() util.RawBytes {
	return util.RawBytes(net.IP(*h).To4())
}

func (h *HostIPv4) IP() net.IP {
	return net.IP(*h)
}

func (h *HostIPv4) String() string {
	return h.IP().String()
}

// Host IPv6 type
// *****************************************
type HostIPv6 net.IP

func (h *HostIPv6) Size() int {
	return HostLenIPv6
}

func (h *HostIPv6) Type() uint8 {
	return HostTypeIPv6
}

func (h *HostIPv6) Pack() util.RawBytes {
	return util.RawBytes(*h)[:HostLenIPv6]
}

func (h *HostIPv6) IP() net.IP {
	return net.IP(*h)
}

func (h *HostIPv6) String() string {
	return h.IP().String()
}

// Host SVC type
// *****************************************
type HostSVC uint16

func (h HostSVC) Size() int {
	return HostLenSVC
}

func (h HostSVC) Type() uint8 {
	return HostTypeSVC
}

func (h HostSVC) Pack() util.RawBytes {
	out := make(util.RawBytes, HostLenSVC)
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
	default:
		name = "UNKNOWN"
	}
	cast := 'A'
	if h.IsMulticast() {
		cast = 'M'
	}
	return fmt.Sprintf("%v %c (0x%04x)", name, cast, uint16(h))
}

func HostFromRaw(b util.RawBytes, htype uint8) (HostAddr, *util.Error) {
	switch htype {
	case HostTypeNone:
		return &HostNone{}, nil
	case HostTypeIPv4:
		h := HostIPv4(b[:HostLenIPv4])
		return &h, nil
	case HostTypeIPv6:
		h := HostIPv6(b[:HostLenIPv6])
		return &h, nil
	case HostTypeSVC:
		h := HostSVC(binary.BigEndian.Uint16(b))
		return &h, nil
	default:
		return nil, util.NewError(ErrorUnknownHostAddrType, "type", htype)
	}
}

func HostFromIP(ip net.IP) HostAddr {
	if ip.To4() != nil {
		h := HostIPv4(ip)
		return &h
	}
	h := HostIPv6(ip)
	return &h
}

func HostLen(htype uint8) (uint8, *util.Error) {
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
		return 0, util.NewError(ErrorUnknownHostAddrType, "type", htype)
	}
	return length, nil
}
