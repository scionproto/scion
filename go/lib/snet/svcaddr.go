// Copyright 2019 Anapaya Systems
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
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/spath"
)

// SVCAddr is the address type for SVC destinations.
type SVCAddr struct {
	IA      addr.IA
	Path    *spath.Path
	NextHop *net.UDPAddr
	SVC     addr.HostSVC
}

// Network implements net.Addr interface.
func (a *SVCAddr) Network() string {
	return "scion"
}

// String implements net.Addr interface.
func (a *SVCAddr) String() string {
	return fmt.Sprintf("%v,%v", a.IA, a.SVC)
}

// GetPath returns a path with attached metadata.
func (a *SVCAddr) GetPath() (Path, error) {
	// Initialize path so it is always ready for use
	var p *spath.Path
	if a.Path != nil {
		p = a.Path.Copy()
		if err := p.InitOffsets(); err != nil {
			return nil, err
		}
	}
	return &partialPath{
		spath:       p,
		underlay:    a.NextHop,
		destination: a.IA,
	}, nil
}

// Copy creates a deep copy of the address.
func (a *SVCAddr) Copy() *SVCAddr {
	if a == nil {
		return nil
	}
	return &SVCAddr{
		IA:      a.IA,
		Path:    a.Path.Copy(),
		NextHop: CopyUDPAddr(a.NextHop),
		SVC:     a.SVC,
	}
}
