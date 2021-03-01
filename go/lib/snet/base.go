// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	// Local and remote SCION addresses (IA, L3, L4)
	listen *net.UDPAddr
	remote *UDPAddr

	// svc address
	svc addr.HostSVC

	// Reference to SCION networking context
	scionNet *SCIONNetwork
}

func (c *scionConnBase) LocalAddr() net.Addr {
	return c.listen
}

func (c *scionConnBase) RemoteAddr() net.Addr {
	return c.remote
}

func (c *scionConnBase) SVC() addr.HostSVC {
	return c.svc
}
