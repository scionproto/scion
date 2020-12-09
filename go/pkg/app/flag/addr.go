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

package flag

import (
	"net"
)

// TCPAddr implements pflags.Value
type TCPAddr net.TCPAddr

func (addr *TCPAddr) Set(input string) error {
	p, err := net.ResolveTCPAddr("tcp", input)
	if err != nil {
		return err
	}
	*addr = TCPAddr(*p)
	return nil
}

func (addr *TCPAddr) UnmarshalText(b []byte) error {
	return addr.Set(string(b))
}

func (addr *TCPAddr) Type() string {
	return "tcp-addr"
}

func (addr *TCPAddr) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

func (addr *TCPAddr) String() string {
	return (*net.TCPAddr)(addr).String()
}

// UDPAddr implements pflags.Value
type UDPAddr net.UDPAddr

func (addr *UDPAddr) Set(input string) error {
	p, err := net.ResolveUDPAddr("udp", input)
	if err != nil {
		return err
	}
	*addr = UDPAddr(*p)
	return nil
}

func (addr *UDPAddr) UnmarshalText(b []byte) error {
	return addr.Set(string(b))
}

func (addr *UDPAddr) Type() string {
	return "udp-addr"
}

func (addr *UDPAddr) MarshalText() ([]byte, error) {
	return []byte(addr.String()), nil
}

func (addr *UDPAddr) String() string {
	return (*net.UDPAddr)(addr).String()
}
