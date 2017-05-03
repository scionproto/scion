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

package overlay

import (
	"net"
)

const (
	// EndhostPort is the overlay port that the dispatcher binds to on non-routers. Subject to
	// change during standardisation.
	EndhostPort = 30041
)

type UDP struct {
	pubIP    *net.IP
	pubPort  int
	bindIP   *net.IP
	bindPort int
	Conn     *net.UDPConn
}

func NewUDP(ip net.IP, port int) *UDP {
	return &UDP{pubIP: &ip, pubPort: port}
}

func (u *UDP) PublicAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: *u.pubIP, Port: u.pubPort}
}

func (u *UDP) BindAddr() *net.UDPAddr {
	ip := u.pubIP
	port := u.pubPort
	if u.bindIP != nil {
		ip = u.bindIP
	}
	if u.bindPort != 0 {
		port = u.bindPort
	}
	return &net.UDPAddr{IP: *ip, Port: port}
}

func (u *UDP) Listen() error {
	var err error
	u.Conn, err = net.ListenUDP("udp", u.BindAddr())
	return err
}

func (u *UDP) Connect(raddr *net.UDPAddr) error {
	var err error
	u.Conn, err = net.DialUDP("udp", u.BindAddr(), raddr)
	return err
}

func (u *UDP) Equal(other *UDP) bool {
	return (u.pubIP.Equal(*other.pubIP) && u.pubPort == other.pubPort &&
		((u.bindIP == nil && other.bindIP == nil) ||
			(u.bindIP.Equal(*other.bindIP) && u.bindPort == other.bindPort)))
}
