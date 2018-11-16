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

package snet

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
)

type scionConnBase struct {
	// Local, remote and bind SCION addresses (IA, L3, L4)
	laddr *Addr
	raddr *Addr
	baddr *Addr

	// svc address
	svc addr.HostSVC

	// Reference to SCION networking context
	scionNet *SCIONNetwork

	// Describes L3 and L4 protocol; currently only udp4 is implemented
	net string
}

func (c *scionConnBase) BindAddr() net.Addr {
	return c.baddr
}

func (c *scionConnBase) BindSnetAddr() *Addr {
	return c.baddr
}

func (c *scionConnBase) LocalAddr() net.Addr {
	return c.laddr
}

func (c *scionConnBase) LocalSnetAddr() *Addr {
	return c.laddr
}

func (c *scionConnBase) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *scionConnBase) RemoteSnetAddr() *Addr {
	return c.raddr
}

func (c *scionConnBase) SVC() addr.HostSVC {
	return c.svc
}
