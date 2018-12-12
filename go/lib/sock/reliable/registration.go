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

	var msg RegistrationMessage
	msg.Command = CmdAlwaysOn | CmdEnableSCMP
	msg.L4Proto = 17
	msg.IA = uint64(r.IA.IAInt())
	msg.Port = uint16(r.PublicAddress.Port)
	msg.AddressType = byte(getIPAddressType(r.PublicAddress.IP))
	msg.Address = []byte(r.PublicAddress.IP)

	if r.BindAddress != nil {
		msg.Command |= CmdBindAddress
		var bindAddress BindAddressLayer
		msg.BindData = &bindAddress
		bindAddress.Port = uint16(r.BindAddress.Port)
		bindAddress.AddressType = byte(getIPAddressType(r.BindAddress.IP))
		bindAddress.Address = []byte(r.BindAddress.IP)
	}
	if r.SVCAddress != addr.SvcNone {
		buffer := make([]byte, 2)
		common.Order.PutUint16(buffer, uint16(r.SVCAddress))
		msg.SVC = buffer
	}
	return msg.SerializeTo(b)
}

func (r *Registration) DecodeFromBytes(b []byte) error {

	var msg RegistrationMessage
	err := msg.DecodeFromBytes(b)
	if err != nil {
		return err
	}

	r.IA = addr.IAInt(msg.IA).IA()
	r.PublicAddress = &net.UDPAddr{
		IP:   net.IP(msg.Address),
		Port: int(msg.Port),
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

// RegistrationMessage is the wire format for a SCION Dispatcher registration
// message.
type RegistrationMessage struct {
	Command     CommandBitField
	L4Proto     uint8
	IA          uint64
	Port        uint16
	AddressType byte
	Address     []byte
	BindData    *BindAddressLayer
	SVC         []byte
}

func (m *RegistrationMessage) SerializeTo(b []byte) (int, error) {
	if len(b) < 13 {
		return 0, common.NewBasicError(ErrBufferTooSmall, nil)
	}
	b[0] = byte(m.Command)
	b[1] = m.L4Proto
	common.Order.PutUint64(b[2:], m.IA)
	common.Order.PutUint16(b[10:], m.Port)
	b[12] = m.AddressType
	copy(b[13:], m.Address)
	if m.BindData != nil {
		_, err := m.BindData.SerializeTo(b[13+len(m.Address):])
		if err != nil {
			return 0, err
		}
	}
	copy(b[13+len(m.Address)+m.BindData.length():], m.SVC)
	return 13 + len(m.Address) + m.BindData.length() + len(m.SVC), nil
}

func (l *RegistrationMessage) DecodeFromBytes(b []byte) error {
	if len(b) < 13 {
		return common.NewBasicError(ErrIncompleteMessage, nil)
	}
	l.Command = CommandBitField(b[0])
	l.L4Proto = b[1]
	l.IA = common.Order.Uint64(b[2:])
	l.Port = common.Order.Uint16(b[10:])
	l.AddressType = b[12]
	if !AddressType(l.AddressType).IsValid() {
		return common.NewBasicError(ErrBadAddressType, nil)
	}
	addressLength := AddressType(l.AddressType).AddressLength()
	if len(b[13:]) < addressLength {
		return common.NewBasicError(ErrIncompleteAddress, nil)
	}
	l.Address = b[13 : 13+addressLength]
	if (l.Command & CmdBindAddress) != 0 {
		var bindData BindAddressLayer
		err := bindData.DecodeFromBytes(b[13+addressLength:])
		if err != nil {
			return err
		}
		l.BindData = &bindData
	}
	switch len(b[13+addressLength+l.BindData.length():]) {
	case 0:
		return nil
	case 1:
		return common.NewBasicError(ErrPayloadTooLong, nil)
	case 2:
		l.SVC = b[13+addressLength+l.BindData.length():]
		return nil
	default:
		return common.NewBasicError(ErrPayloadTooLong, nil)
	}
}

type BindAddressLayer struct {
	Port        uint16
	AddressType byte
	Address     []byte
}

func (l *BindAddressLayer) SerializeTo(b []byte) (int, error) {
	if len(b) < 3 {
		return 0, common.NewBasicError(ErrBufferTooSmall, nil)
	}
	common.Order.PutUint16(b, l.Port)
	b[2] = l.AddressType
	copy(b[3:], l.Address)
	return len(l.Address) + 3, nil
}

func (l *BindAddressLayer) DecodeFromBytes(b []byte) error {
	if len(b) < 3 {
		return common.NewBasicError(ErrIncompleteMessage, nil)
	}
	l.Port = common.Order.Uint16(b[:2])
	l.AddressType = b[2]
	if !AddressType(l.AddressType).IsValid() {
		return common.NewBasicError(ErrBadAddressType, nil)
	}
	addressLength := AddressType(l.AddressType).AddressLength()
	if len(b[3:]) < addressLength {
		return common.NewBasicError(ErrIncompleteAddress, nil)
	}
	l.Address = b[3 : 3+addressLength]
	return nil
}

func (l *BindAddressLayer) length() int {
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
