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

package snetmigrate

import (
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

type emptyPath struct {
	// source is the AS where the path starts.
	source addr.IA
}

func (p *emptyPath) Fingerprint() snet.PathFingerprint {
	return ""
}

func (p *emptyPath) UnderlayNextHop() *net.UDPAddr {
	return nil
}

func (p *emptyPath) Path() *spath.Path {
	return nil
}

func (p *emptyPath) Interfaces() []snet.PathInterface {
	return nil
}

func (p *emptyPath) Destination() addr.IA {
	return p.source
}

func (p *emptyPath) MTU() uint16 {
	return 0
}

func (p *emptyPath) Expiry() time.Time {
	return time.Time{}
}

func (p *emptyPath) Copy() snet.Path {
	if p == nil {
		return nil
	}
	return &emptyPath{
		source: p.source,
	}
}

func (p *emptyPath) String() string {
	return ""
}
