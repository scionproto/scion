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

type CommandBitField uint8

const (
	CmdBindAddress CommandBitField = 0x04
	CmdEnableSCMP  CommandBitField = 0x02
	CmdAlwaysOn    CommandBitField = 0x01
)

// Registration contains metadata for a SCION Dispatcher registration message.
type Registration struct {
	IA            addr.IA
	PublicAddress *net.UDPAddr
	BindAddress   *net.UDPAddr
	SVCAddress    addr.HostSVC
}

func (r *Registration) SerializeTo(b []byte) (int, error) {
	if r.PublicAddress == nil || r.PublicAddress.IP == nil {
		return 0, common.NewBasicError(ErrNoAddress, nil)
	}

	var msg registrationMessage
	msg.Command = CmdAlwaysOn | CmdEnableSCMP
	msg.L4Proto = 17
	msg.IA = uint64(r.IA.IAInt())
	msg.PublicData.SetFromUDPAddr(r.PublicAddress)
	if r.BindAddress != nil {
		msg.Command |= CmdBindAddress
		var bindAddress registrationAddressField
		msg.BindData = &bindAddress
		bindAddress.SetFromUDPAddr(r.BindAddress)
	}
	if r.SVCAddress != addr.SvcNone {
		buffer := make([]byte, 2)
		common.Order.PutUint16(buffer, uint16(r.SVCAddress))
		msg.SVC = buffer
	}
	return msg.SerializeTo(b)
}

func (r *Registration) DecodeFromBytes(b []byte) error {
	var msg registrationMessage
	err := msg.DecodeFromBytes(b)
	if err != nil {
		return err
	}

	r.IA = addr.IAInt(msg.IA).IA()
	r.PublicAddress = &net.UDPAddr{
		IP:   net.IP(msg.PublicData.Address),
		Port: int(msg.PublicData.Port),
	}

	if len(msg.SVC) == 0 {
		r.SVCAddress = addr.SvcNone
	} else {
		r.SVCAddress = addr.HostSVC(common.Order.Uint16(msg.SVC))
	}
	if (msg.Command & CmdBindAddress) != 0 {
		r.BindAddress = &net.UDPAddr{
			IP:   net.IP(msg.BindData.Address),
			Port: int(msg.BindData.Port),
		}
	}
	return nil
}

// registrationMessage is the wire format for a SCION Dispatcher registration
// message.
type registrationMessage struct {
	Command    CommandBitField
	L4Proto    uint8
	IA         uint64
	PublicData registrationAddressField
	BindData   *registrationAddressField
	SVC        []byte
}

func (m *registrationMessage) SerializeTo(b []byte) (int, error) {
	if len(b) < 13 {
		return 0, common.NewBasicError(ErrBufferTooSmall, nil)
	}
	b[0] = byte(m.Command)
	b[1] = m.L4Proto
	common.Order.PutUint64(b[2:], m.IA)
	offset := 10
	if _, err := m.PublicData.SerializeTo(b[offset:]); err != nil {
		return 0, err
	}
	offset += m.PublicData.length()
	if m.BindData != nil {
		if _, err := m.BindData.SerializeTo(b[offset:]); err != nil {
			return 0, err
		}
		offset += m.BindData.length()
	}
	copy(b[offset:], m.SVC)
	offset += len(m.SVC)
	return offset, nil
}

func (l *registrationMessage) DecodeFromBytes(b []byte) error {
	if len(b) < 13 {
		return common.NewBasicError(ErrIncompleteMessage, nil)
	}
	l.Command = CommandBitField(b[0])
	l.L4Proto = b[1]
	l.IA = common.Order.Uint64(b[2:])
	offset := 10
	if err := l.PublicData.DecodeFromBytes(b[offset:]); err != nil {
		return err
	}
	offset += l.PublicData.length()
	if (l.Command & CmdBindAddress) != 0 {
		l.BindData = &registrationAddressField{}
		if err := l.BindData.DecodeFromBytes(b[offset:]); err != nil {
			return err
		}
		offset += l.BindData.length()
	}
	switch len(b[offset:]) {
	case 0:
		return nil
	case 2:
		l.SVC = b[offset:]
		return nil
	default:
		return common.NewBasicError(ErrPayloadTooLong, nil)
	}
}

type registrationAddressField struct {
	Port        uint16
	AddressType byte
	Address     []byte
}

func (l *registrationAddressField) SerializeTo(b []byte) (int, error) {
	if len(b) < l.length() {
		return 0, common.NewBasicError(ErrBufferTooSmall, nil)
	}
	common.Order.PutUint16(b, l.Port)
	b[2] = l.AddressType
	copy(b[3:], l.Address)
	return l.length(), nil
}

func (l *registrationAddressField) DecodeFromBytes(b []byte) error {
	if len(b) < 3 {
		return common.NewBasicError(ErrIncompleteMessage, nil)
	}
	l.Port = common.Order.Uint16(b[:2])
	l.AddressType = b[2]
	if !isValidReliableSockDestination(addr.HostAddrType(l.AddressType)) {
		return common.NewBasicError(ErrBadAddressType, nil)
	}
	addressLength := getAddressLength(addr.HostAddrType(l.AddressType))
	if len(b[3:]) < addressLength {
		return common.NewBasicError(ErrIncompleteAddress, nil)
	}
	l.Address = b[3 : 3+addressLength]
	return nil
}

func (l *registrationAddressField) SetFromUDPAddr(u *net.UDPAddr) {
	l.Port = uint16(u.Port)
	l.AddressType = byte(getIPAddressType(u.IP))
	l.Address = []byte(u.IP)
}

func (l *registrationAddressField) length() int {
	if l == nil {
		return 0
	}
	return 2 + 1 + len(l.Address)
}

type Confirmation struct {
	Port uint16
}

func (c *Confirmation) SerializeTo(b []byte) (int, error) {
	if len(b) < 2 {
		return 0, common.NewBasicError(ErrBufferTooSmall, nil)
	}
	common.Order.PutUint16(b, c.Port)
	return 2, nil
}

func (c *Confirmation) DecodeFromBytes(b []byte) error {
	if len(b) < 2 {
		return common.NewBasicError(ErrIncompletePort, nil)
	}
	c.Port = common.Order.Uint16(b)
	return nil
}
