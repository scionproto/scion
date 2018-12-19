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

package reliable

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

// OverlayPacket contains metadata about a SCION packet going through the
// reliable socket framing protocol.
type OverlayPacket struct {
	Address *net.UDPAddr
	Payload []byte
}

func (p *OverlayPacket) SerializeTo(b []byte) (int, error) {
	var f frame
	f.Cookie = expectedCookie
	f.AddressType = byte(getAddressType(p.Address))
	f.Length = uint32(len(p.Payload))
	if p.Address != nil {
		if err := f.insertAddress(p.Address); err != nil {
			return 0, err
		}
	}
	f.Payload = p.Payload
	return f.SerializeTo(b)
}

func (p *OverlayPacket) DecodeFromBytes(b []byte) error {
	var f frame
	if err := f.DecodeFromBytes(b); err != nil {
		return err
	}
	if f.Cookie != expectedCookie {
		return common.NewBasicError(ErrBadCookie, nil)
	}
	p.Address = f.extractAddress()
	p.Payload = f.Payload
	return nil
}

// frame describes the wire format of the reliable socket framing protocol.
type frame struct {
	Cookie      uint64
	AddressType byte
	Length      uint32
	Address     []byte
	Port        []byte
	Payload     []byte
}

func (f *frame) SerializeTo(b []byte) (int, error) {
	totalLength := f.length()
	if totalLength > len(b) {
		return 0, common.NewBasicError(ErrBufferTooSmall, nil, "have", len(b), "want", totalLength)
	}
	common.Order.PutUint64(b, f.Cookie)
	b[8] = f.AddressType
	common.Order.PutUint32(b[9:], uint32(f.Length))
	copy(b[13:], f.Address)
	copy(b[13+len(f.Address):], f.Port)
	copy(b[13+len(f.Address)+len(f.Port):], f.Payload)
	return totalLength, nil
}

func (f *frame) DecodeFromBytes(data []byte) error {
	if len(data) < f.headerLength() {
		return common.NewBasicError(ErrIncompleteFrameHeader, nil)
	}
	f.Cookie = common.Order.Uint64(data)
	f.AddressType = data[8]
	f.Length = common.Order.Uint32(data[9:])
	offset := 13
	addressType := addr.HostAddrType(f.AddressType)
	if !isValidReliableSockDestination(addressType) {
		return common.NewBasicError(ErrBadAddressType, nil, "type", addressType)
	}
	addrLen := getAddressLength(addressType)
	portLen := getPortLength(addressType)
	if len(data[offset:]) < addrLen {
		return common.NewBasicError(ErrIncompleteAddress, nil)
	}
	f.Address = data[offset : offset+addrLen]
	offset += addrLen
	if len(data[offset:]) < portLen {
		return common.NewBasicError(ErrIncompletePort, nil)
	}
	f.Port = data[offset : offset+portLen]
	offset += portLen
	f.Payload = data[offset:]
	if len(f.Payload) != int(f.Length) {
		return common.NewBasicError(ErrBadLength, nil)
	}
	return nil
}

// length returns the total length of the frame (including payload).
func (f *frame) length() int {
	return f.headerLength() + len(f.Address) + len(f.Port) + len(f.Payload)
}

// header length returns the length of the fixed size start of the frame
// (cookie, address type and payload length field).
func (f *frame) headerLength() int {
	return 8 + 1 + 4
}

func (f *frame) insertAddress(address *net.UDPAddr) error {
	if address.IP == nil || address.IP.IsUnspecified() {
		return common.NewBasicError(ErrNoAddress, nil)
	}
	if address.Port == 0 {
		return common.NewBasicError(ErrNoPort, nil)
	}
	f.Address = []byte(normalizeIP(address.IP))
	f.Port = make([]byte, 2)
	common.Order.PutUint16(f.Port, uint16(address.Port))
	return nil
}

func (f *frame) extractAddress() *net.UDPAddr {
	t := addr.HostAddrType(f.AddressType)
	if t == addr.HostTypeIPv4 || t == addr.HostTypeIPv6 {
		return &net.UDPAddr{
			IP:   net.IP(f.Address),
			Port: int(common.Order.Uint16(f.Port)),
		}
	}
	return nil
}
