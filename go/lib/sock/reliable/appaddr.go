// Copyright 2017 ETH Zurich
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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
)

var (
	NilAppAddr AppAddr
)

func init() {
	a, _ := addr.HostFromRaw(nil, addr.HostTypeNone)
	NilAppAddr = AppAddr{Addr: a, Port: 0}
}

// AppAddr is a L3 + L4 address container, it currently only supports UDP for L4.
type AppAddr struct {
	Addr addr.HostAddr
	Port uint16
}

func AppAddrFromRaw(buf common.RawBytes, addrType addr.HostAddrType) (*AppAddr, error) {
	var a AppAddr
	addrLen, err := addr.HostLen(addrType)
	if err != nil {
		return nil, err
	}
	// Add 2 for port
	if len(buf) < int(addrLen)+2 {
		return nil, common.NewBasicError("Buffer too small for address type", nil,
			"expected", addrLen+2, "actual", len(buf))
	}

	a.Addr, err = addr.HostFromRaw(buf, addrType)
	if err != nil {
		return nil, err
	}
	a.Port = common.Order.Uint16(buf[addrLen:])
	return &a, nil
}

func (a *AppAddr) Write(buf common.RawBytes) (int, error) {
	if len(buf) < a.Len() {
		return 0, common.NewBasicError("Unable to write AppAddr, buffer too small", nil,
			"expected", a.Len(), "actual", len(buf))
	}
	a.writeAddr(buf)
	a.writePort(buf[a.Addr.Size():])
	return a.Len(), nil
}

func (a *AppAddr) Len() int {
	if a.Addr.Type() == addr.HostTypeNone {
		return a.Addr.Size()
	}
	return a.Addr.Size() + 2
}

func (a *AppAddr) writeAddr(buf common.RawBytes) {
	copy(buf, a.Addr.Pack())
}

func (a *AppAddr) writePort(buf common.RawBytes) {
	if a.Addr.Type() == addr.HostTypeNone {
		return
	}
	common.Order.PutUint16(buf, a.Port)
}
