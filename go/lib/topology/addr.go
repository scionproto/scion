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

package topology

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	ErrAtLeastOnePub       = serrors.New("underlay requires at least one public address")
	ErrUnsupportedUnderlay = serrors.New("unsupported underlay")
	ErrUnsupportedAddrType = serrors.New("unsupported address type")
	ErrInvalidPub          = serrors.New("invalid public address")
	ErrInvalidBind         = serrors.New("invalid bind address")
	ErrBindNotSupported    = serrors.New(
		"bind addresses are not supported for this address type")
	ErrCustomUnderlayPortNotSupported = serrors.New("custom underlay port not supported")
	ErrUnderlayPort                   = serrors.New("underlay port set for non-UDP underlay")
	ErrBindAddrEqPubAddr              = serrors.New("bind address equal to Public address")
	ErrMismatchUnderlayAddr           = serrors.New("mismatch underlay type and address")
	ErrMismatchPubAddrType            = serrors.New("mismatch public address and type")
	ErrMismatchBindAddrType           = serrors.New("mismatch bind address and type")
	ErrUnderlayAddressNotFound        = serrors.New("underlay address not found")
	ErrExpectedIPv4FoundIPv6          = serrors.New("expected IPv4 address, but found IPv6 address")
	ErrExpectedIPv6FoundIPv4          = serrors.New("expected IPv6 address, but found IPv4 address")
)

// TopoAddr wraps the possible addresses of a SCION service and describes
// the underlay to be used for contacting said service.
type TopoAddr struct {
	SCIONAddress    *addr.AppAddr
	UnderlayAddress net.Addr
}

func (t *TopoAddr) UnderlayAddr() *net.UDPAddr {
	return t.UnderlayAddress.(*net.UDPAddr)
}

func (t *TopoAddr) String() string {
	return fmt.Sprintf("TopoAddr{SCION: %v, Underlay: %v}", t.SCIONAddress, t.UnderlayAddress)
}
