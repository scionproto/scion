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

	"github.com/scionproto/scion/pkg/addr"
)

// SVCAddr is the address type for SVC destinations.
type SVCAddr struct {
	IA      addr.IA
	Path    DataplanePath
	NextHop *net.UDPAddr
	SVC     addr.SVC
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
	return &partialPath{
		dataplane:   a.Path,
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
		Path:    a.Path,
		NextHop: CopyUDPAddr(a.NextHop),
		SVC:     a.SVC,
	}
}
